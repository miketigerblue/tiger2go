-- Backfill cve_kev from any CISA-KEV-shaped rows already in cve_enriched.
--
-- Safe to run multiple times: ON CONFLICT DO NOTHING means a re-run won't
-- overwrite better data already in cve_kev.
--
-- Run AFTER 20260511_create_cve_kev.sql has been applied.

INSERT INTO cve_kev (
    cve_id,
    vulnerability_name,
    vendor_project,
    product,
    short_description,
    required_action,
    date_added,
    due_date,
    known_ransomware_use,
    notes,
    cwes,
    raw,
    first_seen_at,
    last_seen_at
)
SELECT
    cve_id,
    NULLIF(json ->> 'vulnerabilityName', ''),
    NULLIF(json ->> 'vendorProject', ''),
    NULLIF(json ->> 'product', ''),
    NULLIF(json ->> 'shortDescription', ''),
    NULLIF(json ->> 'requiredAction', ''),
    -- Dates may arrive as ISO strings (YYYY-MM-DD); guard against bad data.
    CASE
        WHEN json ->> 'dateAdded' ~ '^\d{4}-\d{2}-\d{2}$' THEN (json ->> 'dateAdded')::date
        ELSE NULL
    END,
    CASE
        WHEN json ->> 'dueDate' ~ '^\d{4}-\d{2}-\d{2}$' THEN (json ->> 'dueDate')::date
        ELSE NULL
    END,
    -- CISA uses 'Known' / 'Unknown' here
    COALESCE(LOWER(json ->> 'knownRansomwareCampaignUse'), '') = 'known',
    NULLIF(json ->> 'notes', ''),
    -- cwes is an array of strings in the upstream feed
    CASE
        WHEN jsonb_typeof(json -> 'cwes') = 'array'
            THEN ARRAY(SELECT jsonb_array_elements_text(json -> 'cwes'))
        ELSE NULL
    END,
    json,
    modified,
    modified
FROM cve_enriched
WHERE source = 'CISA-KEV'
  AND json IS NOT NULL
  AND jsonb_typeof(json) = 'object'
ON CONFLICT (cve_id) DO NOTHING;

-- Sanity report (read-only, runs after the insert above commits)
SELECT
    (SELECT COUNT(*) FROM cve_enriched WHERE source = 'CISA-KEV') AS kev_rows_in_cve_enriched,
    (SELECT COUNT(*) FROM cve_kev WHERE withdrawn_at IS NULL)     AS active_cve_kev,
    (SELECT COUNT(*) FROM cve_kev WHERE known_ransomware_use)     AS ransomware_known,
    (SELECT COUNT(*) FROM cve_kev WHERE due_date IS NOT NULL)     AS with_due_date;
