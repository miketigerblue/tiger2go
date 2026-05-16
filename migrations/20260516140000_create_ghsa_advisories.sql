-- +goose Up
-- Up --------------------------------------------------------------
-- GHSA (GitHub Security Advisory Database) — higher-fidelity advisories
-- than OSV's GitHub feed, with CVSS + CWE per advisory and richer package
-- vulnerability ranges. Co-references OSV (each GHSA-* maps to one or
-- more CVE-*).
--
-- Schema reference: https://docs.github.com/en/rest/security-advisories

CREATE TABLE IF NOT EXISTS ghsa_advisories (
    ghsa_id          TEXT        PRIMARY KEY,            -- GHSA-xxxx-xxxx-xxxx
    cve_id           TEXT,                               -- denormalised from identifiers[]
    summary          TEXT,
    description      TEXT,
    severity         TEXT,                               -- low / medium / high / critical (GitHub's text enum)
    cvss_v3          NUMERIC,
    cvss_v3_vector   TEXT,
    cvss_v4          NUMERIC,
    cvss_v4_vector   TEXT,
    cwes             TEXT[]      NOT NULL DEFAULT '{}',  -- denormalised from cwes[*].cwe_id
    ecosystems       TEXT[]      NOT NULL DEFAULT '{}',  -- distinct vulnerabilities[*].package.ecosystem
    package_names    TEXT[]      NOT NULL DEFAULT '{}',  -- distinct vulnerabilities[*].package.name
    vulnerabilities  JSONB       NOT NULL,               -- full upstream vulnerabilities[]
    refs             JSONB,                              -- references[] (URL strings)
    published        TIMESTAMPTZ,
    updated          TIMESTAMPTZ,
    withdrawn        TIMESTAMPTZ,
    state            TEXT,                               -- published / withdrawn / triage
    advisory_type    TEXT,                               -- reviewed / unreviewed / malware
    raw              JSONB       NOT NULL,               -- full source record
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE ghsa_advisories IS
  'GitHub Security Advisory Database — per-advisory record with CVSS, CWE, and per-package vulnerability ranges. Co-references OSV via CVE alias.';

CREATE INDEX IF NOT EXISTS idx_ghsa_cve            ON ghsa_advisories (cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ghsa_severity       ON ghsa_advisories (severity);
CREATE INDEX IF NOT EXISTS idx_ghsa_updated        ON ghsa_advisories (updated DESC);
CREATE INDEX IF NOT EXISTS idx_ghsa_ecosystems     ON ghsa_advisories USING gin (ecosystems);
CREATE INDEX IF NOT EXISTS idx_ghsa_package_names  ON ghsa_advisories USING gin (package_names);
CREATE INDEX IF NOT EXISTS idx_ghsa_cwes           ON ghsa_advisories USING gin (cwes);
CREATE INDEX IF NOT EXISTS idx_ghsa_cvss_v3        ON ghsa_advisories (cvss_v3) WHERE cvss_v3 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ghsa_active         ON ghsa_advisories (updated DESC) WHERE withdrawn IS NULL;

-- +goose Down
DROP TABLE IF EXISTS ghsa_advisories;
