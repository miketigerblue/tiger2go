# Tigerfetch PostgREST API (`schema: api`) — Endpoint Guide for Security Awareness & Triage

**Audience:** platform security, SRE, SOC/IR, data governance  
**Service:** PostgREST over PostgreSQL  
**Purpose:** document every exposed endpoint derived from the DB `api` schema, with security implications, triage usage, and practical request examples.

---

## Executive summary (meeting-ready)

### What’s exposed
This PostgREST instance is configured to expose **only** PostgreSQL schema `api`:

- `postgrest/postgrest.conf`: `db-schemas = "api"`
- `postgrest/fly.toml`: `PGRST_DB_SCHEMA = 'api'`

PostgREST automatically turns:
- each **view/materialized view/table** in `api` into a REST resource at `GET /<relation>`
- each **function** in `api` into an RPC endpoint at `POST /rpc/<function>`

### Authentication & privileges (current state)
- Requests without JWT use role: **`postgrest-anon`** (`db-anon-role = "postgrest-anon"`).
- **`postgrest-anon` has `SELECT` on all `api` relation endpoints**.
- **`postgrest-anon` has `EXECUTE` on all exposed `api` functions**.
- **No write capability** for anon: **no `INSERT/UPDATE/DELETE`** on any `api` relation.

### Main risks to call out
1. **Information disclosure:** 
   - `analysis_entries.content` and enrichment JSON arrays can leak sensitive content (copyright text, PII, inadvertent secrets).
   - “Number2” sitreps/insights can include high-signal derived intelligence.
2. **Bulk scraping / competitive intel / pipeline observability leakage:**
   - Stats/campaign/mention endpoints reveal ingestion volume, timing, and focus areas.
3. **Availability:** expensive filters (broad `ilike`, full-text queries, wide sorts) can be used for DoS.

### High-impact controls (recommended)
- Put PostgREST **behind network controls** (Fly private networking) unless it must be public.
- Split roles (least privilege): e.g. `anon_lite` can only read lite endpoints.
- Require JWT for endpoints returning full content or derived intelligence.
- Add rate limiting / WAF rules / caching at the edge.
- Consider disabling public OpenAPI docs in internet-facing environments.

---

## Base URL & discovery

From `postgrest/fly.toml`:
- `PGRST_OPENAPI_SERVER_PROXY_URI = 'https://tigerblue-postgrest.fly.dev'`

Use in examples:

```bash
BASE="https://tigerblue-postgrest.fly.dev"
```

### Service root and OpenAPI
PostgREST supports OpenAPI output (configured with `openapi-mode = "follow-privileges"`).

```bash
# Root
curl -sS "$BASE/"

# OpenAPI JSON (common content negotiation pattern)
curl -sS -H 'Accept: application/openapi+json' "$BASE/" > openapi.json

# Quick look
cat openapi.json | jq '.info, .paths | keys'
```

**Security note:** OpenAPI availability significantly accelerates attacker reconnaissance.

---

## PostgREST query patterns (applies to every `GET /<relation>` endpoint)

### Field selection (projection)
Return only what you need.

```bash
curl -sS "$BASE/analysis_entries_lite?select=analysis_guid,title,severity_level,analysed_at"
```

### Filters
```bash
# equality
curl -sS "$BASE/cve_detail?cve_id=eq.CVE-2024-12345"

# IN list
curl -sS "$BASE/analysis_entries_lite?severity_level=in.(CRITICAL,HIGH)"

# date/time window
curl -sS "$BASE/analysis_entries_lite?analysed_at=gte.2025-12-01&analysed_at=lt.2026-01-01"

# case-insensitive substring match
curl -sS "$BASE/analysis_entries_lite?title=ilike.*ransomware*"
```

### Sorting
```bash
curl -sS "$BASE/analysis_entries_lite?order=analysed_at.desc"
```

### Pagination
PostgREST is configured with `db-max-rows = 1000`. Use HTTP `Range` to paginate safely.

```bash
curl -sS -H 'Range: 0-49' "$BASE/analysis_entries_lite?order=analysed_at.desc"
curl -sS -H 'Range: 50-99' "$BASE/analysis_entries_lite?order=analysed_at.desc"
```

### Counts
```bash
curl -sS -I -H 'Prefer: count=exact' "$BASE/analysis_entries_lite?severity_level=eq.CRITICAL"
```

---

# Complete endpoint inventory

## A) Relation endpoints (read-only via `GET /<name>`)

> **All of these are readable by `postgrest-anon` today.**

### Views
- `GET /analysis_cve_anomalies`
- `GET /analysis_cves_enriched`
- `GET /analysis_cves_enriched_lite`
- `GET /analysis_entries`
- `GET /analysis_entries_campaign`
- `GET /analysis_entries_lite`
- `GET /analysis_search`
- `GET /campaign_latest_seen`
- `GET /campaign_summary`
- `GET /cve_detail`
- `GET /epss_latest`
- `GET /epss_movers_24h`
- `GET /epss_top_latest`
- `GET /kev_cves_lite`
- `GET /number2_daily_insights_latest`
- `GET /number2_hourly_sitreps`
- `GET /number2_hourly_sitreps_latest`
- `GET /nvd_cves_lite`
- `GET /stats_severity_by_source_7d`

### Materialized views
- `GET /analysis_cve_mentions`
- `GET /analysis_cve_mentions_v2`
- `GET /campaign_cve_rollups`

## B) RPC endpoints (callable via `POST /rpc/<function>`)

> **All of these are executable by `postgrest-anon` today.**

- `POST /rpc/first_matching_url`
- `POST /rpc/normalise_campaign_url`
- `POST /rpc/pick_campaign_key`

---

# Endpoint-by-endpoint guide

Each section includes:
- **What it returns** (semantic purpose)
- **Useful columns** (for SOC/triage)
- **Practical examples** (copy/paste)
- **Security notes** (exposure/abuse considerations)

---

## 1) `GET /analysis_entries` (view)

### What it returns
A “full-fat” join over `archive` and `analysis` including:
- article metadata and **full content**
- triage metadata (severity/confidence)
- enrichment arrays (IOCs, CVEs, TTPS, etc.)

### Useful columns
- IDs: `analysis_id` (uuid), `analysis_guid` (text), `archive_id`, `archive_guid`
- Content: `title`, `link`, `published`, `content`, `author`, `categories`
- Triage: `severity_level`, `confidence_pct`, `summary_impact`, `relevance`
- Enrichment JSON: `recommended_actions`, `key_iocs`, `cve_references`, `ttps`, `attack_vectors`, `tools_used`, `malware_families`, `exploit_references`, …

### Practical examples
```bash
# Latest CRITICAL items, keep response lean (avoid content)
curl -sS -H 'Range: 0-49' \
  "$BASE/analysis_entries?severity_level=eq.CRITICAL&order=analysed_at.desc&select=analysis_guid,title,link,analysed_at,confidence_pct,summary_impact,source_name"

# Pull one analysis by GUID
curl -sS "$BASE/analysis_entries?analysis_guid=eq.<GUID>"
```

### Security notes
- **Highest disclosure risk** due to `content` + enrichment arrays.
- Prefer to restrict this endpoint (JWT + role) if anything must be public.

---

## 2) `GET /analysis_entries_lite` (view)

### What it returns
A slimmer view for triage lists (no raw article content) plus computed:
- `severity_rank`
- `ioc_count`, `cve_count`, `action_count`

### Practical examples
```bash
# “My triage queue”: most recent HIGH/CRITICAL
curl -sS -H 'Range: 0-99' \
  "$BASE/analysis_entries_lite?severity_level=in.(CRITICAL,HIGH)&order=analysed_at.desc"

# Only analyses that mention CVEs
curl -sS "$BASE/analysis_entries_lite?cve_count=gt.0&order=analysed_at.desc&select=analysis_guid,title,cve_count,severity_level"
```

### Security notes
- Generally safer to expose than `analysis_entries`.
- Still reveals pipeline focus and timing.

---

## 3) `GET /analysis_entries_campaign` (view)

### What it returns
`analysis_entries_lite` plus `campaign_key` computed by `api.pick_campaign_key(exploit_references, analysis_id)`.

### Practical examples
```bash
# campaign_key for today's critical items
curl -sS "$BASE/analysis_entries_campaign?severity_level=eq.CRITICAL&analysed_at=gte.2025-12-19&select=analysis_guid,title,campaign_key"

# all items in a campaign
curl -sS "$BASE/analysis_entries_campaign?campaign_key=eq.<KEY>&order=analysed_at.asc"
```

### Security notes
- Campaign keys can create stable identifiers useful for defenders and for adversaries profiling your intelligence streams.

---

## 4) `GET /analysis_search` (view)

### What it returns
Search-oriented fields plus a `tsvector document` built from title/summary/relevance/content.

### Practical examples
```bash
# keyword sweep (safe fallback)
curl -sS "$BASE/analysis_search?title=ilike.*cisco*&order=analysed_at.desc" \
  | jq '.[0:10]'

# high-confidence keyword hits (last 7 days)
curl -sS "$BASE/analysis_search?analysed_at=gte.2025-12-12&confidence_pct=gte.80&title=ilike.*zero-day*" \
  | jq '.[0:10]'
```

### Security notes
- Search endpoints can be abused for **enumeration** and **resource exhaustion**.
- Enforce Range and rate limits.

---

## 5) `GET /analysis_cve_mentions` (materialized view)

### What it returns
Per-analysis CVE mentions.

**Columns:** `analysis_id (uuid)`, `analysed_at`, `source_name`, `cve_id`.

### Practical examples
```bash
# all analyses mentioning a given CVE
curl -sS "$BASE/analysis_cve_mentions?cve_id=eq.CVE-2024-12345&select=analysis_id,analysed_at,source_name&order=analysed_at.desc"

# CVEs mentioned by a given source in a window
curl -sS "$BASE/analysis_cve_mentions?source_name=eq.TheHackerNews&analysed_at=gte.2025-12-01&select=cve_id,analysed_at"
```

### Security notes
- Reveals which CVEs your pipeline is tracking and when.
- Materialized views can be **stale** depending on refresh cadence.

---

## 6) `GET /analysis_cve_mentions_v2` (materialized view)

### What it returns
Same column set as `analysis_cve_mentions` (v2 variant).

### Practical examples
```bash
curl -sS "$BASE/analysis_cve_mentions_v2?cve_id=eq.CVE-2024-12345&order=analysed_at.desc"
```

### Security notes
- Differences between v1/v2 counts are useful indicators of parser drift.

---

## 7) `GET /analysis_cve_anomalies` (view)

### What it returns
Counts of “CVE-like” tokens that **do not** match the regex `^CVE-\d{4}-\d{4,}$`.

### Practical examples
```bash
# top anomalies
curl -sS "$BASE/analysis_cve_anomalies?order=mentions.desc" | jq '.[0:25]'
```

### Security notes
- Great for detecting feed poisoning / extraction issues / prompt-injection artifacts.

---

## 8) `GET /analysis_cves_enriched` (view)

### What it returns
CVE mention aggregates joined to NVD-enriched data (`cve_enriched` where `source='NVD'`).

**Columns:** `cve_id`, `mention_count`, `last_seen`, `source`, `cvss_base`, `epss`, `modified`, `json`.

### Practical examples
```bash
# hot CVEs by mentions
curl -sS "$BASE/analysis_cves_enriched?order=mention_count.desc&select=cve_id,mention_count,last_seen,cvss_base,epss" \
  | jq '.[0:25]'

# recently-seen, high EPSS
curl -sS "$BASE/analysis_cves_enriched?epss=gte.0.2&order=last_seen.desc&select=cve_id,epss,cvss_base,last_seen" \
  | jq '.[0:25]'
```

### Security notes
- Returning `json` is heavyweight; prefer `analysis_cves_enriched_lite` unless you explicitly need full NVD JSON.

---

## 9) `GET /analysis_cves_enriched_lite` (view)

### What it returns
CVE mention aggregates with extracted `description_en` rather than full NVD JSON.

### Practical examples
```bash
curl -sS "$BASE/analysis_cves_enriched_lite?order=mention_count.desc&select=cve_id,mention_count,cvss_base,epss,description_en" \
  | jq '.[0:25]'
```

---

## 10) `GET /cve_detail` (view)

### What it returns
A consolidated CVE profile:
- base NVD record
- EPSS latest overlay (percentile)
- KEV overlay (if present)
- mention counts and campaign rollups

### Practical examples
```bash
# one CVE, lean fields
curl -sS "$BASE/cve_detail?cve_id=eq.CVE-2024-12345&select=cve_id,cvss_base,epss,epss_percentile,in_kev,due_date,mention_count,last_seen,description_en"

# patch-now list: KEV + high EPSS
curl -sS "$BASE/cve_detail?in_kev=is.true&epss=gte.0.2&select=cve_id,epss,cvss_base,due_date,required_action&order=epss.desc" \
  | jq '.[0:50]'
```

### Security notes
- Strong prioritization endpoint: if public, it can allow others to infer your vulnerability attention model.

---

## 11) `GET /nvd_cves_lite` (view)

### What it returns
Light NVD view: `cve_id`, `modified`, `cvss_base`, `epss`, `description_en`.

### Practical examples
```bash
curl -sS "$BASE/nvd_cves_lite?cvss_base=gte.9.0&order=modified.desc&select=cve_id,cvss_base,modified,description_en" \
  | jq '.[0:50]'
```

---

## 12) `GET /kev_cves_lite` (view)

### What it returns
CISA KEV derived fields plus `kev_json`.

### Practical examples
```bash
curl -sS "$BASE/kev_cves_lite?date_added=gte.2025-12-01&select=cve_id,vendor,product,required_action,due_date" \
  | jq '.[0:50]'
```

---

## 13) `GET /epss_latest` (view)

### What it returns
Latest EPSS row per CVE.

### Practical examples
```bash
curl -sS "$BASE/epss_latest?cve_id=eq.CVE-2024-12345"
```

---

## 14) `GET /epss_top_latest` (view)

### What it returns
EPSS latest joined with NVD lite.

### Practical examples
```bash
curl -sS -H 'Range: 0-49' "$BASE/epss_top_latest?order=epss.desc"
```

---

## 15) `GET /epss_movers_24h` (view)

### What it returns
24h EPSS deltas.

### Practical examples
```bash
curl -sS "$BASE/epss_movers_24h?order=delta.desc&select=cve_id,epss_today,epss_yday,delta" \
  | jq '.[0:25]'
```

---

## 16) `GET /campaign_cve_rollups` (materialized view)

### What it returns
Per-campaign per-CVE rollups.

**Columns:** `campaign_key`, `cve_id`, `mention_count`, `item_count`, `source_count`, `first_seen`, `last_seen`, `cvss_base`, `epss`, `cve_modified`, `description_en`.

### Practical examples
```bash
# CVEs in a campaign
curl -sS "$BASE/campaign_cve_rollups?campaign_key=eq.<KEY>&order=mention_count.desc" \
  | jq '.[0:50]'
```

### Security notes
- Materialized view staleness matters for IR; document refresh schedule.

---

## 17) `GET /campaign_summary` (view)

### What it returns
Campaign aggregates: `first_seen`, `last_seen`, `distinct_cve_count`, `max_cvss_base`, `max_epss`, `item_mentions`.

### Practical examples
```bash
curl -sS "$BASE/campaign_summary?order=item_mentions.desc" | jq '.[0:25]'
```

---

## 18) `GET /campaign_latest_seen` (view)

### What it returns
Campaign recency + a classifier `campaign_kind`:
- `patch_wave` (>=10 CVEs)
- `active_exploitation` (max_epss >= 0.2)
- `cve_story` otherwise

### Practical examples
```bash
curl -sS "$BASE/campaign_latest_seen?campaign_kind=eq.active_exploitation&order=last_seen.desc" \
  | jq '.[0:25]'
```

---

## 19) `GET /number2_hourly_sitreps` (view)

### What it returns
Hourly situation reports.

**Columns:** `report_id`, `window_start`, `window_end`, `generated_at`, `pipeline_version`, `report (jsonb)`.

### Practical examples
```bash
curl -sS -H 'Range: 0-23' \
  "$BASE/number2_hourly_sitreps?order=generated_at.desc&select=report_id,window_start,window_end,generated_at,pipeline_version"
```

### Security notes
- `report` can contain high-signal derived intelligence; strongly consider gating.

---

## 20) `GET /number2_hourly_sitreps_latest` (view)

### What it returns
Latest sitrep view.

```bash
curl -sS "$BASE/number2_hourly_sitreps_latest"
```

---

## 21) `GET /number2_daily_insights_latest` (view)

### What it returns
Daily insights JSON.

```bash
curl -sS "$BASE/number2_daily_insights_latest" | jq '.'
```

### Security notes
- Derived intelligence tends to be more sensitive than raw feed data.

---

## 22) `GET /stats_severity_by_source_7d` (view)

### What it returns
Counts by `source_name` and `severity_level` for last 7 days.

### Practical examples
```bash
curl -sS "$BASE/stats_severity_by_source_7d" | jq '.[0:100]'
```

### Security notes
- Telemetry side-channel: reveals ingestion volume per source.

---

# RPC endpoints (functions)

PostgREST exposes functions as `/rpc/<name>` and expects JSON body matching arg names.

## 23) `POST /rpc/normalise_campaign_url`
Signature: `normalise_campaign_url(u text) -> text` (immutable)

```bash
curl -sS -X POST "$BASE/rpc/normalise_campaign_url" \
  -H 'Content-Type: application/json' \
  -d '{"u":"https://Example.com/path/?utm_source=rss"}'
```

**Security notes:**
- Even “immutable” functions can be abused for CPU burn; rate limit.

---

## 24) `POST /rpc/pick_campaign_key`
Signature: `pick_campaign_key(exploit_refs json, fallback_id uuid) -> text` (stable)

```bash
curl -sS -X POST "$BASE/rpc/pick_campaign_key" \
  -H 'Content-Type: application/json' \
  -d '{
    "exploit_refs": [{"url":"https://example.com/exploit"}],
    "fallback_id": "00000000-0000-0000-0000-000000000000"
  }'
```

**Security notes:**
- JSON input: treat request bodies as sensitive if you log them.

---

## 25) `POST /rpc/first_matching_url`
Signature: `first_matching_url(refs jsonb, pattern text) -> text` (stable)

```bash
curl -sS -X POST "$BASE/rpc/first_matching_url" \
  -H 'Content-Type: application/json' \
  -d '{
    "refs": [{"url":"https://a.example"},{"url":"https://b.example"}],
    "pattern": "b\\.example"
  }'
```

**Security notes:**
- If `pattern` is treated as regex in implementation, consider **ReDoS** safeguards.

---

# Appendix: “Public vs internal” suggested exposure model

If you need a quick policy decision:

## Safer to expose (still rate limit)
- `analysis_entries_lite`
- `analysis_cves_enriched_lite`
- `nvd_cves_lite`
- `kev_cves_lite`
- `epss_latest`, `epss_top_latest`, `epss_movers_24h`

## Should be authenticated / internal
- `analysis_entries` (contains `content`)
- `analysis_search` (DoS / enumeration risks)
- `analysis_cve_mentions*` (pipeline observability leakage)
- `campaign_*` (campaign correlation and tracking)
- `number2_*` (derived intelligence)
- `stats_severity_by_source_7d` (telemetry)
- RPC endpoints (reduce abuse surface; keep internal unless required)

---

## Appendix: quick demo commands (copy/paste for the meeting)

```bash
BASE="https://tigerblue-postgrest.fly.dev"

# 1) Show exposed endpoints via OpenAPI (if enabled)
curl -sS -H 'Accept: application/openapi+json' "$BASE/" | jq '.paths | keys'

# 2) Show triage queue
curl -sS -H 'Range: 0-20' "$BASE/analysis_entries_lite?severity_level=in.(CRITICAL,HIGH)&order=analysed_at.desc" | jq '.[] | {analysis_guid,title,severity_level,confidence_pct,cve_count,ioc_count}'

# 3) Show “patch now” list (KEV + high EPSS)
curl -sS "$BASE/cve_detail?in_kev=is.true&epss=gte.0.2&select=cve_id,epss,cvss_base,due_date,required_action&order=epss.desc" | jq '.[0:15]'

# 4) Show pipeline hygiene (anomalous CVE tokens)
curl -sS "$BASE/analysis_cve_anomalies?order=mentions.desc" | jq '.[0:15]'
```
