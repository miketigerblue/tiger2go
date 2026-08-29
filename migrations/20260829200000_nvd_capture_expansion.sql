-- +goose Up
-- Up --------------------------------------------------------------
-- Widen the NVD capture. NvdCveItem parsed 5 of the 16 fields NVD 2.0
-- ships, and extractCvssScore read 2 of the 5 metric families that were
-- already being stored. Two separable problems, and only one of them
-- needs NVD to send us anything:
--
--  (a) Fields never parsed at all — published, vulnStatus,
--      sourceIdentifier, cveTags, references. These CANNOT be
--      backfilled: they are not in the stored blob. The columns land
--      NULL here and populate organically as NVD marks CVEs modified,
--      the same way the descriptions/weaknesses capture (added
--      2026-08-05) reached 100% coverage without a cursor reset.
--
--  (b) Data ALREADY sitting in cve_enriched.json->'metrics' that
--      nothing could query, because the metrics blob is stored
--      verbatim but only v3.1/v3.0 were ever read out of it. This
--      backfills completely, below, with no refetch:
--        - 76,564 rows (20% of the table) have a CVSS score in the
--          blob while cvss_base is NULL — 70,872 v2, 5,692 v4.0.
--        - 172,143 rows (45%) carry CISA's SSVC decision points,
--          of which 1,662 say exploitation=active. For comparison the
--          separately-ingested CISA-KEV catalogue holds 1,685 rows.
--
--  (c) A latent bug in the same area. NVD sends naive timestamps
--      ("2026-08-29T18:16:33.473" — no Z, no offset, documented as
--      UTC). The ingester parsed them with time.RFC3339, which fails
--      on every one, and the error path substituted time.Now(). So
--      cve_enriched.modified has been holding the INGEST time rather
--      than NVD's modification time on all 382,817 rows — verified
--      2026-08-29, every row disagreed with json->>'lastModified' by
--      more than 60s. Nothing surfaced it because an ingest timestamp
--      looks entirely plausible there. The true value was in the blob
--      all along, so this is fully repairable here. The ingester is
--      fixed by parseNvdTime.
--
-- Counts above measured 2026-08-29 against 382,817 source='NVD' rows.

ALTER TABLE cve_enriched
    ADD COLUMN IF NOT EXISTS published             TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS vuln_status           TEXT,
    ADD COLUMN IF NOT EXISTS source_identifier     TEXT,
    ADD COLUMN IF NOT EXISTS cve_tags              TEXT[],
    ADD COLUMN IF NOT EXISTS cvss_version          TEXT,
    ADD COLUMN IF NOT EXISTS ssvc_exploitation     TEXT,
    ADD COLUMN IF NOT EXISTS ssvc_automatable      TEXT,
    ADD COLUMN IF NOT EXISTS ssvc_technical_impact TEXT;

COMMENT ON COLUMN cve_enriched.published IS
  'NVD first-publication date. Distinct from `modified` (lastModified): a 2015 CVE revised yesterday has an old published and a recent modified.';
COMMENT ON COLUMN cve_enriched.vuln_status IS
  'NVD analysis state: Analyzed / Modified / Deferred / Rejected / Awaiting Analysis. Rejected rows are withdrawn CVEs — exclude them from findings. Deferred means NVD abandoned analysis, so the row will never gain configurations and can never match an SBOM.';
COMMENT ON COLUMN cve_enriched.cve_tags IS
  'Flattened union of cveTags[].tags — notably "disputed" (~1,499 CVEs NVD-wide).';
COMMENT ON COLUMN cve_enriched.cvss_version IS
  'Which CVSS family cvss_base was taken from: 3.1, 3.0, 4.0 or 2.0. Makes the fallback visible so a v2 score is never mistaken for a v3 one — they are not comparable.';
COMMENT ON COLUMN cve_enriched.ssvc_exploitation IS
  'CISA SSVC v2.0.3 exploitation decision point: none / poc / active. "active" is an exploitation assertion from CISA independent of the KEV catalogue.';

-- (b) + (c) Backfill everything recoverable from what is already
-- stored, in ONE pass.
--
-- The metrics extraction and the `modified` repair are deliberately a
-- single UPDATE rather than two readable ones: each touches nearly
-- every NVD row, and Postgres rewrites the whole row per UPDATE. Two
-- statements means two rewrites on a table already carrying ~14% dead
-- tuples, on a 1GB instance. One pass halves that.
--
-- cvss_base is filled only where NULL, so an existing score is never
-- overwritten. cvss_version is set unconditionally and its CASE order
-- matches the COALESCE order exactly, so the version always names the
-- family the surviving score actually came from.
--
-- Measured on dev (382,087 NVD rows, pgvector pg16, local disk):
-- 19.1s, and cve_enriched grew 816MB -> 921MB (+13%) leaving 382,087
-- dead tuples. The growth is modest because the new row versions
-- largely reuse free space the existing bloat had already left behind
-- — but the dead tuples are real, so run VACUUM (ANALYZE)
-- cve_enriched afterwards rather than waiting for autovacuum.
-- Expect longer than 19s on Fly's 1GB instance.
WITH extracted AS (
    SELECT
        cve_id,
        source,
        CASE
            WHEN json->'metrics'->'cvssMetricV31'->0->'cvssData' ? 'baseScore' THEN '3.1'
            WHEN json->'metrics'->'cvssMetricV30'->0->'cvssData' ? 'baseScore' THEN '3.0'
            WHEN json->'metrics'->'cvssMetricV40'->0->'cvssData' ? 'baseScore' THEN '4.0'
            WHEN json->'metrics'->'cvssMetricV2' ->0->'cvssData' ? 'baseScore' THEN '2.0'
        END AS ver,
        COALESCE(
            json->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore',
            json->'metrics'->'cvssMetricV30'->0->'cvssData'->>'baseScore',
            json->'metrics'->'cvssMetricV40'->0->'cvssData'->>'baseScore',
            json->'metrics'->'cvssMetricV2' ->0->'cvssData'->>'baseScore'
        )::numeric AS score,
        -- SSVC options is an array of single-key objects, not one object:
        -- [{"exploitation":"active"},{"automatable":"no"},...]
        (SELECT o->>'exploitation' FROM jsonb_array_elements(
             json->'metrics'->'ssvcV203'->0->'ssvcData'->'options') o
          WHERE o ? 'exploitation' LIMIT 1) AS expl,
        (SELECT o->>'automatable' FROM jsonb_array_elements(
             json->'metrics'->'ssvcV203'->0->'ssvcData'->'options') o
          WHERE o ? 'automatable' LIMIT 1) AS autom,
        (SELECT o->>'technicalImpact' FROM jsonb_array_elements(
             json->'metrics'->'ssvcV203'->0->'ssvcData'->'options') o
          WHERE o ? 'technicalImpact' LIMIT 1) AS timpact,
        -- (c) The true modification time, recoverable because the blob
        -- kept it. Cast via ::timestamp AT TIME ZONE 'UTC', not
        -- ::timestamptz — the latter would read a naive string using
        -- the session TimeZone, which is not guaranteed to be UTC.
        CASE WHEN json ? 'lastModified'
             THEN (json->>'lastModified')::timestamp AT TIME ZONE 'UTC'
        END AS true_modified
    FROM cve_enriched
    WHERE source = 'NVD'
      AND json ? 'metrics'
)
UPDATE cve_enriched ce
SET cvss_base             = COALESCE(ce.cvss_base, e.score),
    cvss_version          = e.ver,
    ssvc_exploitation     = e.expl,
    ssvc_automatable      = e.autom,
    ssvc_technical_impact = e.timpact,
    modified              = COALESCE(e.true_modified, ce.modified)
FROM extracted e
WHERE ce.cve_id = e.cve_id
  AND ce.source = e.source
  AND ((ce.cvss_base IS NULL AND e.score IS NOT NULL)
       OR ce.cvss_version          IS DISTINCT FROM e.ver
       OR ce.ssvc_exploitation     IS DISTINCT FROM e.expl
       OR ce.ssvc_automatable      IS DISTINCT FROM e.autom
       OR ce.ssvc_technical_impact IS DISTINCT FROM e.timpact
       OR (e.true_modified IS NOT NULL
           AND ce.modified IS DISTINCT FROM e.true_modified));

-- "Published this week", the query the lake could not answer at all.
CREATE INDEX IF NOT EXISTS idx_cve_enriched_published
    ON cve_enriched (published DESC) WHERE published IS NOT NULL;

-- Excluding Rejected/Deferred is a predicate on nearly every analyst
-- query once the column exists, and the distribution is skewed enough
-- (~88% Modified) that a plain btree earns its keep on the tail.
CREATE INDEX IF NOT EXISTS idx_cve_enriched_vuln_status
    ON cve_enriched (vuln_status) WHERE vuln_status IS NOT NULL;

-- 1,662 rows of 382,817. A partial index makes "what does CISA say is
-- being exploited" a lookup rather than a scan.
CREATE INDEX IF NOT EXISTS idx_cve_enriched_ssvc_active
    ON cve_enriched (cve_id) WHERE ssvc_exploitation = 'active';

CREATE INDEX IF NOT EXISTS idx_cve_enriched_cve_tags
    ON cve_enriched USING gin (cve_tags) WHERE cve_tags IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_cve_enriched_cve_tags;
DROP INDEX IF EXISTS idx_cve_enriched_ssvc_active;
DROP INDEX IF EXISTS idx_cve_enriched_vuln_status;
DROP INDEX IF EXISTS idx_cve_enriched_published;

ALTER TABLE cve_enriched
    DROP COLUMN IF EXISTS ssvc_technical_impact,
    DROP COLUMN IF EXISTS ssvc_automatable,
    DROP COLUMN IF EXISTS ssvc_exploitation,
    DROP COLUMN IF EXISTS cvss_version,
    DROP COLUMN IF EXISTS cve_tags,
    DROP COLUMN IF EXISTS source_identifier,
    DROP COLUMN IF EXISTS vuln_status,
    DROP COLUMN IF EXISTS published;
