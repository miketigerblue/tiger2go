-- +goose Up
-- Up --------------------------------------------------------------
-- archive INSERT -> pg_notify('article_ingested', guid)
--
-- Lets tiger-eye drop the 60s polling loop. Tigerfetch INSERTs a new
-- feed entry into archive, this trigger fires, Postgres queues a
-- NOTIFY that's sent on commit. tiger-eye's listener connection wakes
-- the enrichment loop immediately (sub-second latency vs up-to-60s
-- polling lag).
--
-- Notes
-- -----
--   * AFTER INSERT (rolled-back transactions don't generate notifies
--     — pg_notify queues are flushed on commit only).
--   * Payload is the bare guid. asyncpg listeners receive (conn, pid,
--     channel, payload) — payload is sufficient for tiger-eye to know
--     which row is ready, but the listener treats it as a debounced
--     wake signal anyway (the next poll cycle catches up by batch).
--   * No UPDATE trigger here — re-enrichment policy on edits is a
--     separate decision (input_hash compare on poll handles it).

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION archive_notify_ingested()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Bare guid as payload; channel name is "article_ingested".
    -- pg_notify silently no-ops if payload exceeds 8 KB which is well
    -- beyond any plausible guid; no guard needed.
    PERFORM pg_notify('article_ingested', NEW.guid);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_archive_notify_ingested ON archive;

CREATE TRIGGER trg_archive_notify_ingested
    AFTER INSERT ON archive
    FOR EACH ROW
    EXECUTE FUNCTION archive_notify_ingested();

COMMENT ON FUNCTION archive_notify_ingested() IS
    'Fires NOTIFY on the article_ingested channel after each archive INSERT — drives tiger-eye listener-based wakeups';

-- Down ------------------------------------------------------------
-- +goose Down
DROP TRIGGER IF EXISTS trg_archive_notify_ingested ON archive;
DROP FUNCTION IF EXISTS archive_notify_ingested();
