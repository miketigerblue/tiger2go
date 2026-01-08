CREATE TABLE IF NOT EXISTS ingest_state (
    source TEXT PRIMARY KEY,
    cursor TEXT NOT NULL
);
