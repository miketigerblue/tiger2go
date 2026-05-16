-- +goose Up
-- Up --------------------------------------------------------------
-- abuse.ch ThreatFox — IOC feed keyed by malware family, covering
-- IP addresses, domains, URLs, and file hashes that URLhaus' URL-only
-- feed does not. Each IOC carries a confidence score (0-100) and
-- malware family / malpedia mapping, which join cleanly to
-- analysis.key_iocs and analysis_malware in the analysis schema.
--
-- API: https://threatfox-api.abuse.ch/api/v1/  (POST JSON, Auth-Key header)
-- Auth required since 2024 — see SOURCES-TIERED.md.

CREATE TABLE IF NOT EXISTS threatfox_iocs (
    ioc_id              BIGINT      PRIMARY KEY,             -- ThreatFox numeric id
    ioc                 TEXT        NOT NULL,                -- the IOC value (ip:port / domain / url / hash)
    ioc_type            TEXT        NOT NULL,                -- ip:port / domain / url / md5_hash / sha1_hash / sha256_hash / ...
    threat_type         TEXT,                                -- botnet_cc / payload_delivery / payload / ...
    malware             TEXT,                                -- malpedia slug (win.lockbit, ...)
    malware_alias       TEXT,                                -- comma-separated aliases
    malware_printable   TEXT,                                -- human label
    malware_malpedia    TEXT,                                -- malpedia URL
    confidence_level    INTEGER,                             -- 0-100
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    reporter            TEXT,
    reference           TEXT,
    tags                TEXT[]      NOT NULL DEFAULT '{}',
    anonymous           BOOLEAN     NOT NULL DEFAULT FALSE,
    raw                 JSONB       NOT NULL,                -- full upstream record
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE threatfox_iocs IS
  'abuse.ch ThreatFox IOC feed. Joins to analysis.key_iocs (by ioc value) and analysis_malware (by malware family).';

CREATE INDEX IF NOT EXISTS idx_threatfox_ioc            ON threatfox_iocs (ioc);
CREATE INDEX IF NOT EXISTS idx_threatfox_ioc_type       ON threatfox_iocs (ioc_type);
CREATE INDEX IF NOT EXISTS idx_threatfox_threat_type    ON threatfox_iocs (threat_type);
CREATE INDEX IF NOT EXISTS idx_threatfox_malware        ON threatfox_iocs (malware);
CREATE INDEX IF NOT EXISTS idx_threatfox_first_seen     ON threatfox_iocs (first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_threatfox_last_seen      ON threatfox_iocs (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_threatfox_confidence     ON threatfox_iocs (confidence_level DESC);
CREATE INDEX IF NOT EXISTS idx_threatfox_tags           ON threatfox_iocs USING gin (tags);

-- +goose Down
DROP TABLE IF EXISTS threatfox_iocs;
