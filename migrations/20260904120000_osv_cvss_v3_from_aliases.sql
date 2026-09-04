-- +goose Up
-- osv_vulns.cvss_v3 has been NULL on every row since the OSV ingester
-- shipped: extractCvssV3 reads a trailing numeric off the severity
-- string, and OSV advisories carry only the vector. Two consumers
-- filter on the column (a severity floor in each), so any floor
-- returned nothing.
--
-- The ingester now resolves the score through the advisory's CVE
-- aliases in cve_enriched, restricted to the v3.x family — cvss_base
-- can be a v2.0 or v4.0 score, and this column is named cvss_v3. The
-- upsert only rewrites a row when OSV marks it modified, so existing
-- rows are filled here, once, with the same rule.
--
-- Scope: live advisories with aliases (withdrawn ones are excluded by
-- every reader). Each row is one pkey lookup on cve_enriched per alias;
-- measured 2026-09-04 at roughly 1ms per candidate row, so expect on
-- the order of a minute and one dead tuple per row filled. Run
-- VACUUM (ANALYZE) osv_vulns afterwards in a quiet window.
UPDATE osv_vulns o
SET cvss_v3 = s.score
FROM (
    SELECT o2.id,
           (SELECT c.cvss_base
            FROM cve_enriched c
            WHERE c.cve_id = ANY(o2.aliases)
              AND c.source = 'NVD'
              AND c.cvss_version IN ('3.1', '3.0')
            ORDER BY c.cvss_version DESC, c.cvss_base DESC
            LIMIT 1) AS score
    FROM osv_vulns o2
    WHERE o2.cvss_v3 IS NULL
      AND o2.aliases IS NOT NULL
      AND o2.withdrawn IS NULL
) s
WHERE o.id = s.id
  AND s.score IS NOT NULL;

-- +goose Down
-- Not reversible in a meaningful way: the column was NULL before, and a
-- score resolved from NVD is not wrong. Left in place.
SELECT 1;
