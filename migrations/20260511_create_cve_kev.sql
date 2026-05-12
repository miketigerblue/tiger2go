-- +goose Up
-- Up --------------------------------------------------------------
-- CISA Known Exploited Vulnerabilities (KEV) as a first-class table.
--
-- Previously KEV records were squatting in cve_enriched with source='CISA-KEV',
-- which abuses the (cve_id, source) PK semantics — KEV is an *attribute* of a
-- CVE, not a separate authoritative source competing with NVD/MITRE.
--
-- This table mirrors the KEV catalogue schema published at:
--   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
--
-- Backfill from existing rows is performed in a separate post-migration step
-- so this migration stays a pure schema change.

CREATE TABLE IF NOT EXISTS cve_kev (
    cve_id                  TEXT        PRIMARY KEY,
    vulnerability_name      TEXT,
    vendor_project          TEXT,
    product                 TEXT,
    short_description       TEXT,
    required_action         TEXT,
    date_added              DATE,
    due_date                DATE,
    known_ransomware_use    BOOLEAN     NOT NULL DEFAULT FALSE,
    notes                   TEXT,
    cwes                    TEXT[],

    -- Full original record from the KEV feed (defensive — we keep everything)
    raw                     JSONB,

    -- Lifecycle
    first_seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- If CISA removes a CVE from the catalogue we mark it withdrawn rather
    -- than deleting the row, so the historical record is preserved.
    withdrawn_at            TIMESTAMPTZ
);

-- Active KEV entries (most queries)
CREATE INDEX IF NOT EXISTS idx_cve_kev_active
    ON cve_kev (date_added DESC)
    WHERE withdrawn_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_cve_kev_due_date
    ON cve_kev (due_date)
    WHERE withdrawn_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_cve_kev_ransomware
    ON cve_kev (cve_id)
    WHERE known_ransomware_use = TRUE AND withdrawn_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_cve_kev_vendor_product
    ON cve_kev (vendor_project, product);

COMMENT ON TABLE  cve_kev IS 'CISA Known Exploited Vulnerabilities catalogue — one row per CVE, first-class attribute (not a cve_enriched source)';
COMMENT ON COLUMN cve_kev.cve_id               IS 'CVE identifier — primary key';
COMMENT ON COLUMN cve_kev.known_ransomware_use IS 'Set by CISA when use in ransomware campaigns is documented';
COMMENT ON COLUMN cve_kev.due_date             IS 'BOD 22-01 federal remediation deadline';
COMMENT ON COLUMN cve_kev.withdrawn_at         IS 'Set if CISA removes the CVE from the active KEV catalogue (preserves history)';

-- Down ------------------------------------------------------------
-- +goose Down
DROP TABLE IF EXISTS cve_kev;
