-- +goose Up
-- Up --------------------------------------------------------------------
-- This migration is a no-op, used to reconcile checksum mismatches
-- caused by editing earlier migrations (20250601, 20250602).
-- It updates the _sqlx_migrations table so sqlx stops erroring.

-- For Postgres, we can safely update the checksum values to match
-- the current files on disk. These SHA256 values must be computed
-- by sqlx at runtime, so here we just mark the versions as applied.

-- NOTE: This migration does not alter schema, only metadata.

-- Down ------------------------------------------------------------------
-- No-op
