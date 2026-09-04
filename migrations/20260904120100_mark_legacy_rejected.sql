-- +goose Up
-- Up --------------------------------------------------------------
-- Backfill vuln_status='Rejected' for legacy NVD rows whose stored blob
-- pre-dates the vulnStatus capture (20260829200000_nvd_capture_expansion).
--
-- Why
-- ---
--   vuln_status is populated forward-only: it is set when NVD re-emits a
--   record, so the vast majority of rows still carry NULL. Consumers that
--   exclude rejected CVEs must therefore use
--     vuln_status IS DISTINCT FROM 'Rejected'
--   and a NULL status silently keeps a rejected CVE in ranking, alerting
--   and exposure lanes.
--
--   NVD marks a rejected record unambiguously in the description:
--   the English description begins with the literal '** REJECT **'.
--   That text is already in the stored blob, so the status can be derived
--   today without waiting for the record to be re-fetched.
--
-- Scope
-- -----
--   Only source='NVD' rows with a NULL vuln_status. Rows that already
--   carry a status (of any value) are left alone — NVD is the authority
--   and a later re-fetch will overwrite the derived value anyway.
--
-- History trigger
-- ---------------
--   Deliberately ordered BEFORE 20260904120200 (history trigger extension):
--   under the current guard a vuln_status-only change does not produce a
--   cve_enriched_history row, so this backfill leaves no synthetic noise
--   in the audit log.

UPDATE cve_enriched
   SET vuln_status = 'Rejected'
 WHERE source = 'NVD'
   AND vuln_status IS NULL
   AND json->'descriptions'->0->>'value' LIKE '** REJECT **%';

-- +goose Down
-- Not reversible: the derived value is indistinguishable from an
-- NVD-supplied one once written. Safe to leave in place.
SELECT 1;
