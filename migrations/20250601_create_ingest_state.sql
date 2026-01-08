-- +goose Up
-- Up --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ingest_state (
    source TEXT PRIMARY KEY,
    cursor TEXT NOT NULL
);

-- Down ------------------------------------------------------------------
-- NOTE: Skipping DROP to avoid breaking dependent views in shared DBs
-- DROP TABLE IF EXISTS ingest_state;
