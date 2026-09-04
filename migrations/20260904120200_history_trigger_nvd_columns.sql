-- +goose Up
-- Up --------------------------------------------------------------
-- Extend cve_enriched change-capture to the columns promoted by
-- 20260829200000_nvd_capture_expansion.
--
-- Before this migration the trigger guard only compared
-- (json, cvss_base, epss, modified). A change to any of the eight newer
-- columns — published, vuln_status, source_identifier, cve_tags,
-- cvss_version, ssvc_exploitation, ssvc_automatable, ssvc_technical_impact —
-- was ignored unless something else moved in the same UPDATE, so a
-- vulnStatus transition (Analyzed → Rejected) or an SSVC exploitation
-- change (none → poc → active) left no audit row and no changed_fields key.
--
-- Changes
-- -------
--   * cve_enriched_history gains prev_vuln_status, prev_ssvc_exploitation
--     and prev_cvss_version so the three transitions people actually ask
--     about ("when did it get rejected?", "when did CISA flag active
--     exploitation?", "when did the score become a v4 score?") can be
--     answered without diffing prev_json.
--   * The no-op guard covers all twelve scalar/array columns.
--   * changed_fields gains synthetic keys for each new column, following
--     the existing '__cvss_base__' convention:
--       __published__, __vuln_status__, __source_identifier__, __cve_tags__,
--       __cvss_version__, __ssvc_exploitation__, __ssvc_automatable__,
--       __ssvc_technical_impact__

ALTER TABLE cve_enriched_history
    ADD COLUMN IF NOT EXISTS prev_vuln_status       TEXT,
    ADD COLUMN IF NOT EXISTS prev_ssvc_exploitation TEXT,
    ADD COLUMN IF NOT EXISTS prev_cvss_version      TEXT;

COMMENT ON COLUMN cve_enriched_history.prev_vuln_status IS
    'OLD.vuln_status at capture time (NULL on INSERT, or when the row pre-dated vulnStatus capture).';
COMMENT ON COLUMN cve_enriched_history.prev_ssvc_exploitation IS
    'OLD.ssvc_exploitation at capture time: none | poc | active.';
COMMENT ON COLUMN cve_enriched_history.prev_cvss_version IS
    'OLD.cvss_version at capture time: 2.0 | 3.0 | 3.1 | 4.0.';

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
            (cve_id, source, op, prev_json, prev_cvss_base, prev_epss, prev_modified,
             prev_vuln_status, prev_ssvc_exploitation, prev_cvss_version, changed_fields)
        VALUES
            (NEW.cve_id, NEW.source, 'I', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '{}');
        RETURN NEW;

    ELSIF TG_OP = 'UPDATE' THEN
        -- Skip no-op updates — these happen when the ingestor re-writes the
        -- same payload. Compare every promoted column, not just the four
        -- that existed when this trigger was first written.
        IF (OLD.json, OLD.cvss_base, OLD.epss, OLD.modified,
            OLD.published, OLD.vuln_status, OLD.source_identifier, OLD.cve_tags,
            OLD.cvss_version, OLD.ssvc_exploitation, OLD.ssvc_automatable, OLD.ssvc_technical_impact)
           IS NOT DISTINCT FROM
           (NEW.json, NEW.cvss_base, NEW.epss, NEW.modified,
            NEW.published, NEW.vuln_status, NEW.source_identifier, NEW.cve_tags,
            NEW.cvss_version, NEW.ssvc_exploitation, NEW.ssvc_automatable, NEW.ssvc_technical_impact) THEN
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
        IF OLD.published IS DISTINCT FROM NEW.published THEN
            changed := array_append(changed, '__published__');
        END IF;
        IF OLD.vuln_status IS DISTINCT FROM NEW.vuln_status THEN
            changed := array_append(changed, '__vuln_status__');
        END IF;
        IF OLD.source_identifier IS DISTINCT FROM NEW.source_identifier THEN
            changed := array_append(changed, '__source_identifier__');
        END IF;
        IF OLD.cve_tags IS DISTINCT FROM NEW.cve_tags THEN
            changed := array_append(changed, '__cve_tags__');
        END IF;
        IF OLD.cvss_version IS DISTINCT FROM NEW.cvss_version THEN
            changed := array_append(changed, '__cvss_version__');
        END IF;
        IF OLD.ssvc_exploitation IS DISTINCT FROM NEW.ssvc_exploitation THEN
            changed := array_append(changed, '__ssvc_exploitation__');
        END IF;
        IF OLD.ssvc_automatable IS DISTINCT FROM NEW.ssvc_automatable THEN
            changed := array_append(changed, '__ssvc_automatable__');
        END IF;
        IF OLD.ssvc_technical_impact IS DISTINCT FROM NEW.ssvc_technical_impact THEN
            changed := array_append(changed, '__ssvc_technical_impact__');
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
            (cve_id, source, op, prev_json, prev_cvss_base, prev_epss, prev_modified,
             prev_vuln_status, prev_ssvc_exploitation, prev_cvss_version, changed_fields)
        VALUES
            (OLD.cve_id, OLD.source, 'U', OLD.json, OLD.cvss_base, OLD.epss, OLD.modified,
             OLD.vuln_status, OLD.ssvc_exploitation, OLD.cvss_version, changed);
        RETURN NEW;

    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO cve_enriched_history
            (cve_id, source, op, prev_json, prev_cvss_base, prev_epss, prev_modified,
             prev_vuln_status, prev_ssvc_exploitation, prev_cvss_version, changed_fields)
        VALUES
            (OLD.cve_id, OLD.source, 'D', OLD.json, OLD.cvss_base, OLD.epss, OLD.modified,
             OLD.vuln_status, OLD.ssvc_exploitation, OLD.cvss_version, '{}');
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- The trigger binding is unchanged (CREATE OR REPLACE swaps the body in
-- place), but re-create it defensively so a database that somehow lost the
-- trigger picks it up again.
DROP TRIGGER IF EXISTS trg_cve_enriched_history ON cve_enriched;

CREATE TRIGGER trg_cve_enriched_history
    AFTER INSERT OR UPDATE OR DELETE ON cve_enriched
    FOR EACH ROW
    EXECUTE FUNCTION cve_enriched_capture_history();

-- Down ------------------------------------------------------------
-- +goose Down
-- Restore the four-column guard from 20260512_create_cve_enriched_history.
-- The three prev_* columns are kept (dropping them would lose captured data).
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
        IF (OLD.json, OLD.cvss_base, OLD.epss, OLD.modified)
           IS NOT DISTINCT FROM
           (NEW.json, NEW.cvss_base, NEW.epss, NEW.modified) THEN
            RETURN NEW;
        END IF;

        IF OLD.cvss_base IS DISTINCT FROM NEW.cvss_base THEN
            changed := array_append(changed, '__cvss_base__');
        END IF;
        IF OLD.epss IS DISTINCT FROM NEW.epss THEN
            changed := array_append(changed, '__epss__');
        END IF;
        IF OLD.modified IS DISTINCT FROM NEW.modified THEN
            changed := array_append(changed, '__modified__');
        END IF;

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
