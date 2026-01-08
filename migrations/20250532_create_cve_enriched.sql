-- +goose Up
-- Up --------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cve_enriched (
    cve_id      TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'NVD',   -- e.g. 'NVD', 'CERT-FR'
    json        JSONB   NOT NULL,                 -- full enriched record
    cvss_base   NUMERIC,                          -- handy scalar for queries
    epss        NUMERIC,                          -- optional extra score
    modified    TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (cve_id, source)
);

CREATE INDEX IF NOT EXISTS idx_cve_enriched_cvss   ON cve_enriched (cvss_base);
CREATE INDEX IF NOT EXISTS idx_cve_enriched_epss   ON cve_enriched (epss);
CREATE INDEX IF NOT EXISTS idx_cve_enriched_mod    ON cve_enriched (modified DESC);

-- Down ------------------------------------------------------------

-- NOTE: Skipping DROP to avoid breaking dependent views in shared DBs
-- DROP TABLE IF EXISTS cve_enriched;
