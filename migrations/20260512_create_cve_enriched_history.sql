-- +goose Up
-- Up --------------------------------------------------------------
-- cve_enriched_history — append-only change-capture log for cve_enriched.
--
-- Today cve_enriched is overwritten in place on every NVD/MITRE refresh.
-- That means we silently lose CVSS rescores, vulnStatus transitions,
-- description amendments, and CPE-config edits — all of which are useful
-- for "why did this CVE's score change?" debugging and for compliance-grade
-- audit trails.
--
-- Design notes
-- ------------
--   * One row per state-change observed on cve_enriched (INSERT / UPDATE
--     where any column actually changed / DELETE). We skip no-op UPDATEs.
--   * We store the *previous* row's content, so the timeline reconstructs
--     by joining history (older snapshots) against the live cve_enriched row
--     (current state). For INSERTs prev_* is NULL.
--   * changed_fields surfaces which top-level keys in the json payload
--     actually moved, so you can filter for "show me rows where CVSS rescore
--     happened" without parsing every diff.

CREATE TABLE IF NOT EXISTS cve_enriched_history (
    history_id          BIGSERIAL    PRIMARY KEY,
    cve_id              TEXT         NOT NULL,
    source              TEXT         NOT NULL,
    captured_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    op                  CHAR(1)      NOT NULL CHECK (op IN ('I','U','D')),

    -- Previous state (NULL on INSERT)
    prev_json           JSONB,
    prev_cvss_base      NUMERIC,
    prev_epss           NUMERIC,
    prev_modified       TIMESTAMPTZ,

    -- Which top-level json keys (and/or surfaced scalars) actually changed.
    -- Includes the synthetic keys '__cvss_base__', '__epss__', '__modified__'
    -- when those scalar columns moved.
    changed_fields      TEXT[]       NOT NULL DEFAULT '{}'::text[]
);

CREATE INDEX IF NOT EXISTS idx_cve_history_cve_id_captured
    ON cve_enriched_history (cve_id, captured_at DESC);

CREATE INDEX IF NOT EXISTS idx_cve_history_captured
    ON cve_enriched_history (captured_at DESC);

-- Partial index for the common "what changed today?" dashboard
CREATE INDEX IF NOT EXISTS idx_cve_history_changed_fields
    ON cve_enriched_history USING GIN (changed_fields);

COMMENT ON TABLE cve_enriched_history IS
    'Append-only change log for cve_enriched. One row per actual state-change. prev_* columns hold the OLD value; current state is in cve_enriched.';

-- ---------------------------------------------------------------------------
-- Trigger function: capture diffs
-- ---------------------------------------------------------------------------

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cve_enriched_capture_history()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    changed TEXT[] := '{}';
    k TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO cve_enriched_history
            (cve_id, source, op, prev_json, prev_cvss_base, prev_epss, prev_modified, changed_fields)
        VALUES
            (NEW.cve_id, NEW.source, 'I', NULL, NULL, NULL, NULL, '{}');
        RETURN NEW;

    ELSIF TG_OP = 'UPDATE' THEN
        -- Skip no-op updates — these happen when ingestor re-writes the same
        -- payload. Cheap shortcut: if the whole row is DISTINCT, do work.
        IF (OLD.json, OLD.cvss_base, OLD.epss, OLD.modified)
           IS NOT DISTINCT FROM
           (NEW.json, NEW.cvss_base, NEW.epss, NEW.modified) THEN
            RETURN NEW;
        END IF;

        -- Surface scalar column changes
        IF OLD.cvss_base IS DISTINCT FROM NEW.cvss_base THEN
            changed := array_append(changed, '__cvss_base__');
        END IF;
        IF OLD.epss IS DISTINCT FROM NEW.epss THEN
            changed := array_append(changed, '__epss__');
        END IF;
        IF OLD.modified IS DISTINCT FROM NEW.modified THEN
            changed := array_append(changed, '__modified__');
        END IF;

        -- Top-level json key diff
        IF OLD.json IS DISTINCT FROM NEW.json THEN
            FOR k IN
                SELECT key FROM (
                    SELECT jsonb_object_keys(OLD.json) AS key
                    UNION
                    SELECT jsonb_object_keys(NEW.json) AS key
                ) keys
                WHERE OLD.json -> key IS DISTINCT FROM NEW.json -> key
            LOOP
                changed := array_append(changed, k);
            END LOOP;
        END IF;

        INSERT INTO cve_enriched_history
            (cve_id, source, op, prev_json, prev_cvss_base, prev_epss, prev_modified, changed_fields)
        VALUES
            (OLD.cve_id, OLD.source, 'U', OLD.json, OLD.cvss_base, OLD.epss, OLD.modified, changed);
        RETURN NEW;

    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO cve_enriched_history
            (cve_id, source, op, prev_json, prev_cvss_base, prev_epss, prev_modified, changed_fields)
        VALUES
            (OLD.cve_id, OLD.source, 'D', OLD.json, OLD.cvss_base, OLD.epss, OLD.modified, '{}');
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_cve_enriched_history ON cve_enriched;

CREATE TRIGGER trg_cve_enriched_history
    AFTER INSERT OR UPDATE OR DELETE ON cve_enriched
    FOR EACH ROW
    EXECUTE FUNCTION cve_enriched_capture_history();

-- Down ------------------------------------------------------------
-- +goose Down
DROP TRIGGER IF EXISTS trg_cve_enriched_history ON cve_enriched;
DROP FUNCTION IF EXISTS cve_enriched_capture_history();
DROP TABLE IF EXISTS cve_enriched_history;
