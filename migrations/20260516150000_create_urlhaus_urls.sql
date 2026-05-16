-- +goose Up
-- Up --------------------------------------------------------------
-- abuse.ch URLhaus — public CSV feed of malicious URLs keyed by malware
-- family. Used for IOC validation: when an LLM-extracted URL appears in
-- this table, we can confirm it's a known C2 / malware-drop, with the
-- malware family/tag for downstream joining to analysis_malware.
--
-- Source: https://urlhaus.abuse.ch/downloads/csv_recent/ (no auth)
-- Schema reference: https://urlhaus.abuse.ch/api/

CREATE TABLE IF NOT EXISTS urlhaus_urls (
    id              TEXT        PRIMARY KEY,            -- URLhaus internal numeric id
    url             TEXT        NOT NULL,
    url_status      TEXT,                               -- online / offline / unknown
    threat          TEXT,                               -- malware_download / etc.
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    date_added      TIMESTAMPTZ,
    last_online     TIMESTAMPTZ,
    urlhaus_link    TEXT,
    reporter        TEXT,
    raw             TEXT        NOT NULL,               -- original CSV row for round-trip preservation
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE urlhaus_urls IS
  'abuse.ch URLhaus malicious URL feed. Joins to analysis.key_iocs[type=url] for IOC validation.';

CREATE INDEX IF NOT EXISTS idx_urlhaus_url        ON urlhaus_urls (url);
CREATE INDEX IF NOT EXISTS idx_urlhaus_threat     ON urlhaus_urls (threat);
CREATE INDEX IF NOT EXISTS idx_urlhaus_date_added ON urlhaus_urls (date_added DESC);
CREATE INDEX IF NOT EXISTS idx_urlhaus_tags       ON urlhaus_urls USING gin (tags);
CREATE INDEX IF NOT EXISTS idx_urlhaus_online     ON urlhaus_urls (last_online DESC) WHERE url_status = 'online';

-- +goose Down
DROP TABLE IF EXISTS urlhaus_urls;
