-- +goose Up
-- Up --------------------------------------------------------------
-- Metasploit Framework module metadata — the same exploit-commodity
-- signal as Nuclei templates, but a different audience. Metasploit
-- modules generally ship later than Nuclei templates, but indicate a
-- weaponised exploit (post-exploitation, payloads, ranking-graded
-- reliability) rather than just a scanner check.
--
-- Rapid7 publishes a pre-extracted JSON cache of all module metadata
-- at db/modules_metadata_base.json in the framework repo. We pull
-- that single 10 MB file rather than parsing Ruby.
--
-- Source: github.com/rapid7/metasploit-framework

CREATE TABLE IF NOT EXISTS msf_modules (
    fullname         TEXT        PRIMARY KEY,             -- e.g. "exploit/linux/http/nginx_chunked_size"
    name             TEXT,
    module_type      TEXT,                                -- exploit / auxiliary / post / payload / encoder / evasion / nops
    rank             INTEGER,                             -- Metasploit numeric rank (0-600)
    rank_label       TEXT,                                -- manual / low / average / normal / good / great / excellent
    disclosure_date  DATE,
    description      TEXT,
    authors          TEXT[]      NOT NULL DEFAULT '{}',
    refs             TEXT[]      NOT NULL DEFAULT '{}',   -- raw references (CVE-…, OSVDB-…, URL-…, EDB-…)
    cves             TEXT[]      NOT NULL DEFAULT '{}',   -- denormalised from refs
    platforms        TEXT[]      NOT NULL DEFAULT '{}',
    aliases          TEXT[]      NOT NULL DEFAULT '{}',
    raw              JSONB       NOT NULL,                -- full upstream record
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE msf_modules IS
  'Metasploit Framework module metadata — when a CVE gets an MSF module, weaponised exploit availability is confirmed. Source: db/modules_metadata_base.json.';

CREATE INDEX IF NOT EXISTS idx_msf_module_type      ON msf_modules (module_type);
CREATE INDEX IF NOT EXISTS idx_msf_rank             ON msf_modules (rank DESC);
CREATE INDEX IF NOT EXISTS idx_msf_disclosure       ON msf_modules (disclosure_date DESC) WHERE disclosure_date IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_msf_cves             ON msf_modules USING gin (cves);
CREATE INDEX IF NOT EXISTS idx_msf_platforms        ON msf_modules USING gin (platforms);
CREATE INDEX IF NOT EXISTS idx_msf_first_seen       ON msf_modules (first_seen_at DESC);

-- +goose Down
DROP TABLE IF EXISTS msf_modules;
