-- Example query: biggest EPSS movers over 24h (today vs yesterday)
-- Requires two days in epss_daily.

WITH today AS (
  SELECT cve_id, epss AS epss_today
  FROM epss_daily
  WHERE as_of = CURRENT_DATE
),
 yday AS (
  SELECT cve_id, epss AS epss_yday
  FROM epss_daily
  WHERE as_of = CURRENT_DATE - INTERVAL '1 day'
)
SELECT
  today.cve_id,
  today.epss_today,
  yday.epss_yday,
  (today.epss_today - yday.epss_yday) AS delta
FROM today
JOIN yday USING (cve_id)
ORDER BY delta DESC
LIMIT 50;
