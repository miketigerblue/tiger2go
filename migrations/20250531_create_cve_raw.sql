-- +goose Up
-- Up -------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cve_raw (
    cve_id    TEXT        NOT NULL,
    source    TEXT        NOT NULL DEFAULT 'MITRE', -- allows future sources
    json      JSONB       NOT NULL,                 -- exact payload from API
    modified  TIMESTAMPTZ NOT NULL,                 -- last-modified in upstream
    PRIMARY KEY (cve_id, source)
);

-- Fast look-ups for polling delta queries
CREATE INDEX IF NOT EXISTS idx_cve_raw_modified
    ON cve_raw (modified DESC);

-- Down -----------------------------------------------------------------------

-- NOTE: Skipping DROP to avoid breaking dependent views in shared DBs
-- DROP TABLE IF EXISTS cve_raw;
