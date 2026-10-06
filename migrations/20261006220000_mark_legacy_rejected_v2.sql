-- +goose Up
-- Up --------------------------------------------------------------
-- Second pass at 20260904120100_mark_legacy_rejected. That migration
-- matched the NVD 1.x description prefix '** REJECT **', which no row in
-- this lake carries: NVD 2.0 writes 'Rejected reason: ...'. Measured
-- 2026-10-06 on production: 0 rows matched the old prefix, 18,301 rows
-- start with the new one, and 18,162 of those still had a NULL
-- vuln_status (65 carrying an EPSS score, so visible to EPSS-only lanes).
--
-- Scope is unchanged: source='NVD' rows with a NULL status only. NVD
-- remains the authority and a re-fetch overwrites the derived value.
--
-- History trigger
-- ---------------
--   Since 20260904120200 the history guard covers vuln_status, so this
--   UPDATE would write 18k audit rows all stamped with the migration
--   time, answering "when was it rejected?" with the wrong date. The
--   trigger is switched off for the duration of this transaction only;
--   goose runs the migration in one transaction, so a failure re-enables
--   it with the rollback.

ALTER TABLE cve_enriched DISABLE TRIGGER trg_cve_enriched_history;

UPDATE cve_enriched
   SET vuln_status = 'Rejected'
 WHERE source = 'NVD'
   AND vuln_status IS NULL
   AND left(json->'descriptions'->0->>'value', 15) = 'Rejected reason';

ALTER TABLE cve_enriched ENABLE TRIGGER trg_cve_enriched_history;

-- +goose Down
-- Not reversible: the derived value is indistinguishable from an
-- NVD-supplied one once written. Safe to leave in place.
SELECT 1;
