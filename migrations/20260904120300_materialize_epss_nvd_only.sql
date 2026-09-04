-- +goose Up
-- Up --------------------------------------------------------------
-- Restrict materialize_epss_to_cve_enriched() to source='NVD'.
--
-- The original function joined epss_daily → cve_enriched on cve_id alone,
-- so any legacy source='CISA-KEV' mirror row sharing a cve_id was also
-- stamped with an EPSS score. Those rows have no CVSS, no NVD metadata and
-- (as of this release) nothing writes them any more — see
-- internal/cve/kev.go. Scoring them keeps them looking "live" to any read
-- that forgets its source filter, and each nightly delta fires the
-- cve_enriched_history trigger for a row nobody should be reading.
--
-- Behaviour is otherwise identical: idempotent, updates only rows whose
-- score changed, returns (updated_rows, max_as_of). Not run here — the
-- next scheduled call picks the new body up.

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
          AND ce.source = 'NVD'
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
  'Updates cve_enriched.epss (source=NVD rows only) with the latest score per CVE from epss_daily partitions. Idempotent — safe to run on a schedule.';

-- +goose Down
-- Restore the unfiltered body from 20260516_materialize_epss_to_cve_enriched.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION materialize_epss_to_cve_enriched()
RETURNS TABLE(updated_rows bigint, max_as_of date) AS $$
DECLARE
    n bigint;
    latest_date date;
BEGIN
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
