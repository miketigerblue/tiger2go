-- +goose Up
-- Up --------------------------------------------------------------
-- Comparison views showing what the May-2026 migration actually changed.
--
-- The views reference the `legacy.*` schema (restored from the prod
-- fly.io dump — see tiger-eye/docs/MIGRATION-2026-05.md). That schema
-- only exists on the dev box where the restore was performed; CI
-- environments and fresh deployments don't have it. We therefore guard
-- view creation with a schema-existence check so this migration is a
-- no-op anywhere `legacy.analysis` isn't present.
--
-- Dynamic EXECUTE is required because Postgres parses the CREATE VIEW
-- statement at migration time — wrapping it in an IF block alone
-- isn't enough; the SQL must be a string the parser only touches in
-- the branch that actually runs.

-- +goose StatementBegin
DO $do$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'legacy' AND table_name = 'analysis'
    ) THEN
        RAISE NOTICE 'Skipping comparison views: legacy schema not present (only built on dev box after Phase 2 of MIGRATION-2026-05).';
        RETURN;
    END IF;

    EXECUTE $sql$
        CREATE OR REPLACE VIEW public.v_actor_normalisation_demo AS
        WITH legacy_raw AS (
            SELECT lower(trim(value::text, '"')) AS raw_name, COUNT(*) AS n
            FROM legacy.analysis l
            CROSS JOIN LATERAL json_array_elements(l.potential_threat_actors) AS value
            WHERE l.potential_threat_actors::text NOT IN ('[]', 'null')
            GROUP BY 1
        ),
        legacy_totals AS (
            SELECT
                SUM(n)::bigint                  AS total_raw_mentions,
                COUNT(*)::bigint                AS distinct_raw_strings_lowercased,
                (SELECT COUNT(*) FROM legacy.analysis
                 WHERE potential_threat_actors::text NOT IN ('[]','null'))::bigint
                                                AS source_analyses
            FROM legacy_raw
        ),
        new_totals AS (
            SELECT
                COUNT(*)::bigint                AS canonical_entities,
                COUNT(*) FILTER (WHERE category IS NOT NULL)::bigint            AS categorised,
                COUNT(*) FILTER (WHERE attribution_country IS NOT NULL)::bigint AS with_country,
                (SELECT COUNT(*) FROM public.analysis_actor)::bigint            AS total_links
            FROM public.threat_actors
        )
        SELECT
            lt.source_analyses                  AS legacy_analyses_with_actors,
            lt.total_raw_mentions               AS legacy_raw_mentions,
            lt.distinct_raw_strings_lowercased  AS legacy_distinct_strings,
            nt.canonical_entities               AS new_canonical_entities,
            nt.categorised                      AS new_categorised,
            nt.with_country                     AS new_with_country_attribution,
            nt.total_links                      AS new_total_linked_mentions,
            ROUND(lt.distinct_raw_strings_lowercased::numeric / NULLIF(nt.canonical_entities, 0), 1)
                                                AS noise_reduction_ratio
        FROM legacy_totals lt, new_totals nt;
    $sql$;
    COMMENT ON VIEW public.v_actor_normalisation_demo IS
        'Single-row summary of the actor-normalisation cleanup: legacy raw mentions vs new canonical entities.';

    EXECUTE $sql$
        CREATE OR REPLACE VIEW public.v_kev_demotion AS
        SELECT
            k.cve_id,
            k.vulnerability_name                                AS new_vuln_name,
            k.vendor_project                                    AS new_vendor,
            k.product                                           AS new_product,
            k.known_ransomware_use                              AS new_known_ransomware_use,
            k.due_date                                          AS new_due_date,
            array_length(k.cwes, 1)                             AS new_cwe_count,

            (l.json ->> 'vulnerabilityName')                    AS legacy_vuln_name_from_json,
            (l.json ->> 'vendorProject')                        AS legacy_vendor_from_json,
            (l.json ->> 'product')                              AS legacy_product_from_json,
            (l.json ->> 'knownRansomwareCampaignUse')           AS legacy_krcu_text,
            (l.json ->> 'dateAdded')                            AS legacy_date_added_text,
            jsonb_array_length(COALESCE(l.json -> 'cwes', '[]'::jsonb))
                                                                AS legacy_cwe_count,

            CASE
                WHEN l.cve_id IS NULL THEN 'legacy MISSING (not in legacy.cve_enriched)'
                WHEN k.known_ransomware_use AND (l.json ->> 'knownRansomwareCampaignUse') = 'Unknown'
                                              THEN 'legacy lost: known_ransomware_use boolean was string "Unknown"'
                ELSE 'present in both'
            END                                                 AS migration_note
        FROM public.cve_kev k
        LEFT JOIN legacy.cve_enriched l ON l.cve_id = k.cve_id AND l.source = 'CISA-KEV'
        ORDER BY k.date_added DESC NULLS LAST;
    $sql$;
    COMMENT ON VIEW public.v_kev_demotion IS
        'Per-CVE side-by-side of public.cve_kev typed columns vs same fields trapped in legacy.cve_enriched.json.';

    EXECUTE $sql$
        CREATE OR REPLACE VIEW public.v_analysis_comparison AS
        SELECT
            p.guid,
            p.entry_title                                       AS title,
            p.feed_title                                        AS source,

            l.severity_level                                    AS legacy_severity,
            p.severity_level                                    AS new_severity,
            (l.severity_level = p.severity_level)               AS severity_agrees,

            l.confidence                                        AS legacy_confidence_text,
            p.confidence                                        AS new_confidence_int,

            p.threat_type                                       AS new_threat_type,

            p.model_id                                          AS new_model_id,
            p.prompt_version                                    AS new_prompt_version,
            p.pipeline_version                                  AS new_pipeline_version,

            COALESCE(jsonb_array_length(p.potential_threat_actors), 0)  AS new_actor_mentions,
            json_array_length(l.potential_threat_actors)                AS legacy_actor_mentions,
            (SELECT COUNT(*) FROM public.analysis_actor WHERE analysis_id = p.id)
                                                                AS new_canonical_actors_linked,

            l.analysed_at                                       AS legacy_analysed_at,
            p.analysed_at                                       AS new_analysed_at,
            (p.analysed_at - l.analysed_at)                     AS new_minus_legacy_age
        FROM public.analysis p
        JOIN legacy.analysis l ON l.guid = p.guid
        ORDER BY p.analysed_at DESC;
    $sql$;
    COMMENT ON VIEW public.v_analysis_comparison IS
        'Per-GUID side-by-side of v0.1.x (legacy) vs v0.2.x (new) enrichment for overlapping articles.';

    RAISE NOTICE 'Comparison views created (legacy schema present).';
END
$do$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP VIEW IF EXISTS public.v_analysis_comparison;
DROP VIEW IF EXISTS public.v_kev_demotion;
DROP VIEW IF EXISTS public.v_actor_normalisation_demo;
-- +goose StatementEnd
