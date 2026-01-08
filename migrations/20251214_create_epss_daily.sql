-- +goose Up
-- Up --------------------------------------------------------------
-- EPSS daily history (kept forever). We partition by month for scale.
--
-- EPSS source: FIRST.org EPSS API https://api.first.org/data/v1/epss
--
-- Notes:
-- - EPS scores and percentiles are stored as NUMERIC for exactness.
-- - raw JSON is optional but useful for audits.

CREATE TABLE IF NOT EXISTS epss_daily (
    as_of       DATE        NOT NULL,
    cve_id      TEXT        NOT NULL,
    epss        NUMERIC     NOT NULL,
    percentile  NUMERIC,
    raw         JSONB,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (as_of, cve_id)
) PARTITION BY RANGE (as_of);

-- Helpful indexes (will be created on each partition in the ingestor)
CREATE INDEX IF NOT EXISTS idx_epss_daily_cve_id ON epss_daily (cve_id);
CREATE INDEX IF NOT EXISTS idx_epss_daily_as_of_epss ON epss_daily (as_of, epss DESC);

-- View: biggest EPSS movers over 24h (today vs yesterday)
-- (If you want arbitrary ranges later, we can add a parametric RPC via PostgREST.)
CREATE OR REPLACE VIEW v_epss_movers_24h AS
WITH today AS (
  SELECT cve_id, epss AS epss_today, percentile AS percentile_today
  FROM epss_daily
  WHERE as_of = CURRENT_DATE
),
 yday AS (
  SELECT cve_id, epss AS epss_yday, percentile AS percentile_yday
  FROM epss_daily
  WHERE as_of = CURRENT_DATE - INTERVAL '1 day'
)
SELECT
  today.cve_id,
  today.epss_today,
  yday.epss_yday,
  (today.epss_today - yday.epss_yday) AS delta,
  today.percentile_today,
  yday.percentile_yday
FROM today
JOIN yday USING (cve_id)
ORDER BY delta DESC;

-- Down ------------------------------------------------------------
-- NOTE: Skipping DROP to avoid breaking dependent views in shared DBs
-- DROP VIEW IF EXISTS v_epss_movers_24h;
-- DROP TABLE IF EXISTS epss_daily;
