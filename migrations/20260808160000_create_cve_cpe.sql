-- +goose Up
-- Up --------------------------------------------------------------
-- CPE applicability — the authoritative "which product does this CVE
-- affect" mapping, exploded from NVD's configurations[] into rows.
--
-- Why this table exists: the NVD ingestor deliberately dropped
-- `configurations` as "large", which left 371,789 stored CVEs with no
-- vendor/product attribution at all. The only structured product mapping
-- in the lake was CISA KEV — 1,662 CVEs, 0.45% of the corpus. Declared-
-- estate matching (the products a customer BUYS, which no SBOM covers)
-- was therefore limited to what CISA had already confirmed as exploited,
-- plus whatever an OSINT article happened to name. "Which CVEs affect
-- FortiOS 7.2.4" was not answerable from our own database.
--
-- Stored exploded rather than as raw JSONB because every query against it
-- is "given vendor+product+version, which CVEs" — a shape a GIN index on
-- a blob serves badly and a btree on (vendor, product) serves well.
--
-- One row per cpeMatch node. A CVE with several affected products has
-- several rows; a product affected in several version ranges has several
-- rows. Both are correct: matching ORs across them.

CREATE TABLE IF NOT EXISTS cve_cpe (
    cve_id                  TEXT        NOT NULL,
    -- CPE 2.3 components, already lowercased by the spec. `part` is
    -- a/o/h (application/OS/hardware) — kept because "we run the
    -- hardware appliance, not the OS" is a real distinction on an edge
    -- device, and an estate entry knows which it means.
    part                    TEXT        NOT NULL,
    vendor                  TEXT        NOT NULL,
    product                 TEXT        NOT NULL,
    -- The version field from the CPE URI itself. '*' means "any version,
    -- see the range columns"; a literal version means exactly that one.
    version                 TEXT        NOT NULL DEFAULT '*',
    update_field            TEXT        NOT NULL DEFAULT '*',
    -- Range bounds from the cpeMatch node. NULL means unbounded on that
    -- side. Kept as text: CPE versions are not semver and comparison is
    -- done by the caller's comparator, not by Postgres.
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including   TEXT,
    version_end_excluding   TEXT,
    -- NVD's own flag. `false` means the CPE is listed as a running
    -- environment rather than the vulnerable component — matching on
    -- those would tell a customer their OS is vulnerable because some
    -- application that runs on it is.
    vulnerable              BOOLEAN     NOT NULL DEFAULT true,
    criteria                TEXT        NOT NULL,            -- the full cpe23Uri, for provenance
    match_criteria_id       TEXT,
    first_seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Surrogate key: the natural key would have to include the four
    -- range columns, and Postgres does not allow NULLs in a primary key.
    -- Uniqueness is maintained by rewriting a CVE's rows wholesale on
    -- re-ingest rather than by a constraint, which also handles NVD
    -- REMOVING an applicability statement — an upsert never would.
    id                      BIGSERIAL   PRIMARY KEY
);

-- The lookup every caller makes.
CREATE INDEX IF NOT EXISTS cve_cpe_product_idx
    ON cve_cpe (vendor, product) WHERE vulnerable;
CREATE INDEX IF NOT EXISTS cve_cpe_cve_idx ON cve_cpe (cve_id);
-- Fuzzy vendor/product lookup for the declared-estate matcher, which
-- gets "SonicWall" typed by a human and needs "sonicwall".
CREATE INDEX IF NOT EXISTS cve_cpe_product_only_idx
    ON cve_cpe (product) WHERE vulnerable;

-- +goose Down
DROP TABLE IF EXISTS cve_cpe;
