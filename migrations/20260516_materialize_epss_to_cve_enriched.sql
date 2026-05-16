-- +goose Up
-- Up --------------------------------------------------------------
-- Materialise the latest EPSS score per CVE from epss_daily (partitioned)
-- into cve_enriched.epss. Until this migration, cve_enriched.epss was NULL
-- for every row even though ~334K CVEs have current EPSS scores in the
-- daily partitions — the data was unjoinable in the simple `WHERE epss >= X`
-- form most analyst queries assume.
--
-- The function is idempotent and safe to re-run nightly (or after each
-- EPSS pull). It updates only the rows whose score actually changed.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION materialize_epss_to_cve_enriched()
RETURNS TABLE(updated_rows bigint, max_as_of date) AS $$
DECLARE
    n bigint;
    latest_date date;
BEGIN
    -- Latest EPSS score per cve_id across all partitions
    WITH latest AS (
        SELECT DISTINCT ON (cve_id) cve_id, epss, as_of
        FROM public.epss_daily
        ORDER BY cve_id, as_of DESC
    ),
    upd AS (
        UPDATE public.cve_enriched ce
        SET epss = latest.epss
        FROM latest
        WHERE ce.cve_id = latest.cve_id
          AND (ce.epss IS DISTINCT FROM latest.epss)
        RETURNING 1
    )
    SELECT COUNT(*) INTO n FROM upd;

    SELECT MAX(as_of) INTO latest_date FROM public.epss_daily;

    RETURN QUERY SELECT n, latest_date;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

COMMENT ON FUNCTION materialize_epss_to_cve_enriched() IS
  'Updates cve_enriched.epss with the latest score per CVE from epss_daily partitions. Idempotent — safe to run on a schedule.';

-- Run it once now so the migration completes the data-quality fix immediately.
-- Subsequent EPSS pulls should call this function (cron / tigerfetch post-fetch hook / pg_cron etc.).
SELECT materialize_epss_to_cve_enriched();

-- +goose Down
DROP FUNCTION IF EXISTS materialize_epss_to_cve_enriched();
