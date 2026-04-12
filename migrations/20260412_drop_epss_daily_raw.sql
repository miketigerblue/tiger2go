-- +goose Up
-- Drop the redundant raw JSONB column from epss_daily.
-- The column duplicates cve_id, as_of, epss, and percentile as JSON.
-- The Go ingestor never populates it — CopyFrom skips it entirely.
-- Dropping it reclaims ~25-30% of table size (~900MB/month at scale).
--
-- Note: ALTER TABLE on a partitioned table propagates to all partitions.

ALTER TABLE epss_daily DROP COLUMN IF EXISTS raw;

-- +goose Down
ALTER TABLE epss_daily ADD COLUMN IF NOT EXISTS raw JSONB;
