-- +goose Up
-- Up --------------------------------------------------------------
-- OSV (Open Source Vulnerabilities) — per-ecosystem advisories that NVD
-- systematically misses for npm / PyPI / Maven / Go / RubyGems / crates.io
-- supply-chain CVEs. Joins to tiger-watch's SBOM matching via the
-- package_names[] denormalisation.
--
-- Schema: https://ossf.github.io/osv-schema/

CREATE TABLE IF NOT EXISTS osv_vulns (
    id              TEXT        PRIMARY KEY,                 -- PYSEC-2024-1 / GHSA-xxxx / OSV-2023-1
    schema_version  TEXT,
    ecosystem       TEXT        NOT NULL,                    -- PyPI / npm / Go / Maven / RubyGems / crates.io / ...
    package_names   TEXT[]      NOT NULL DEFAULT '{}',       -- denormalised affected[*].package.name for GIN search
    summary         TEXT,
    details         TEXT,
    aliases         TEXT[],                                  -- CVE-2024-... and other tracker IDs
    related         TEXT[],
    affected        JSONB       NOT NULL,                    -- the full affected[] from the OSV record
    refs            JSONB,                                   -- references[]
    severity        JSONB,                                   -- severity[] (CVSS_V2, CVSS_V3, etc.)
    cvss_v3         NUMERIC,                                 -- denormalised score for fast threshold filtering
    published       TIMESTAMPTZ,
    modified        TIMESTAMPTZ,
    withdrawn       TIMESTAMPTZ,                             -- non-NULL if upstream withdrew the advisory
    raw             JSONB       NOT NULL,                    -- full source record — round-trip preservation
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE osv_vulns IS
  'OSV (Open Source Vulnerabilities) feed — per-ecosystem advisories that complement NVD for supply-chain CVEs. See https://ossf.github.io/osv-schema/';

CREATE INDEX IF NOT EXISTS idx_osv_ecosystem      ON osv_vulns (ecosystem);
CREATE INDEX IF NOT EXISTS idx_osv_modified       ON osv_vulns (modified DESC);
CREATE INDEX IF NOT EXISTS idx_osv_package_names  ON osv_vulns USING gin (package_names);
CREATE INDEX IF NOT EXISTS idx_osv_aliases        ON osv_vulns USING gin (aliases);
CREATE INDEX IF NOT EXISTS idx_osv_cvss_v3        ON osv_vulns (cvss_v3) WHERE cvss_v3 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_osv_active         ON osv_vulns (ecosystem, modified DESC) WHERE withdrawn IS NULL;

-- +goose Down
DROP TABLE IF EXISTS osv_vulns;
