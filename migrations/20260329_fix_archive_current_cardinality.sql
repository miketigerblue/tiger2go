-- +goose Up
-- Fix cardinality: unique constraints on archive and current must include
-- feed_url so the same guid/link from two different feeds is stored as two
-- distinct rows rather than colliding.
--
-- Root cause: guid falls back to item.Link when a feed item has no GUID.
-- Multiple OSINT feeds (news aggregators, government CSIRT feeds) commonly
-- link to the same advisory URL (CISA, NVD, etc.), producing the same guid
-- from different sources. With UNIQUE(guid), the second feed's record is
-- silently dropped from archive and last-write-wins in current, losing the
-- originating feed context.
--
-- Fix: composite UNIQUE(guid, feed_url) on both tables.
-- The ingestor ON CONFLICT clauses are updated to match.

-- archive: replace guid-only index with (guid, feed_url) composite
DROP INDEX IF EXISTS archive_guid_key;
CREATE UNIQUE INDEX IF NOT EXISTS archive_guid_feed_key ON archive (guid, feed_url);

-- current: replace guid-only index with (guid, feed_url) composite
DROP INDEX IF EXISTS current_guid_key;
CREATE UNIQUE INDEX IF NOT EXISTS current_guid_feed_key ON current (guid, feed_url);

-- +goose Down
DROP INDEX IF EXISTS archive_guid_feed_key;
CREATE UNIQUE INDEX IF NOT EXISTS archive_guid_key ON archive (guid);

DROP INDEX IF EXISTS current_guid_feed_key;
CREATE UNIQUE INDEX IF NOT EXISTS current_guid_key ON current (guid);
