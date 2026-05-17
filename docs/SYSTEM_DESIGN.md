<p align="center">
  <img src="../tigerfetch_hunt_the_signal.png" alt="TigerFetch" width="200" />
</p>

# TigerFetch System Design Document

> **Version:** 1.4.0 | **Date:** 2026-05-17 | **Status:** Production
> **Service:** `tigerfetch` | **Language:** Go 1.26.1 | **Database:** PostgreSQL 16 (pgvector-enabled)

---

## 1. Overview

TigerFetch is a single-binary cybersecurity OSINT ingestion service. It continuously collects threat intelligence from **22 RSS/Atom feeds** and **10 structured sources** (NVD, CISA KEV, FIRST EPSS, OSV, GHSA, URLhaus, ThreatFox, MalwareBazaar, Nuclei templates, Metasploit module metadata), normalises the data, and stores it in PostgreSQL for downstream consumption.

Two companion services sit on the same lake but are **not** in this binary:

- **tiger-eye** — Python LLM enrichment pipeline. Reads `archive` items, writes structured analysis to `analysis`, computes pgvector embeddings into `analysis_embedding`, canonicalises threat actors and malware families.
- **tiger-watch** — Python SBOM service. Joins ingested SBOM packages against the OSV/GHSA universe with proper version-range evaluation.

TigerFetch itself is designed as an **operational control plane** — not a user-facing API — optimised for reliability, idempotency, and observability at modest scale. Downstream consumers (tiger-eye, tiger-watch, PostgREST analyst surface, the o2 voice agent) read from the lake; they do not call into TigerFetch.

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Single binary, zero runtime deps** | One Go binary with embedded migrations |
| **Idempotent ingestion** | `ON CONFLICT` clauses + cursor tracking + `IS DISTINCT FROM` upsert guards prevent duplicates |
| **Fail-safe isolation** | Each data source runs in its own goroutine; one failure cannot cascade |
| **Observable by default** | 60+ Prometheus metrics, structured logging, health endpoint, four provisioned Grafana dashboards |
| **Secure by construction** | HTML sanitisation, parameterised SQL, non-root container, no secrets in image |
| **Lake-shaped storage** | Everything denormalises to typed columns for hot queries *and* preserves a `raw` jsonb for round-trip fidelity |

---

## 2. Architecture

### 2.1 System Context (C1)

```
                                  +-----------------+
                                  |   TigerFetch    |
                                  |   (tigerfetch)  |
                                  +--------+--------+
                                           |
   +------------------+----------+---------+----------+--------------+---------+
   |                  |          |         |          |              |         |
+--v----+ +---v---+ +--v--+ +---v---+ +---v---+ +----v----+ +-------v------+ +v---+
| 22 RSS| | NVD   | | KEV | | EPSS  | | OSV   | | GHSA    | | abuse.ch x3  | |MSF +|
| Feeds | | (NIST)| |(CISA| |(FIRST)| |11 eco | |GitHub   | | URLhaus /    | |    |
|       | |       | |     | |       | |feeds  | |REST API | | ThreatFox /  | |Nucle|
|       | |       | |     | |       | |       | |         | | MalwareBazaar| |  i  |
+-------+ +-------+ +-----+ +-------+ +-------+ +---------+ +--------------+ +----+
                                                                          |
                                                +-------------------------v---+
                                                |   PostgreSQL 16             |
                                                |   (pgvector-enabled)        |
                                                +------+-------+---------+----+
                                                       |       |         |
                                            +----------v-+   +-v-----+ +-v---------+
                                            | Prometheus |   |tiger- | | tiger-eye |
                                            | :9090      |   |watch  | | (Python   |
                                            | (scrapes 3 |   |(SBOM) | | enrichment)|
                                            |  jobs)     |   |       | |           |
                                            +-----+------+   +-------+ +-----------+
                                                  |
                                            +-----v-----+
                                            | Grafana   |
                                            | :3000     |
                                            | (4 dash-  |
                                            |  boards)  |
                                            +-----------+
```

The three Prometheus scrape jobs are `tigerfetch` (this binary, port 9101),
`tiger-eye` (Python enrichment service), and `tiger-watch` (SBOM
service). Grafana auto-loads four dashboards: `tigerfetch-overview`,
`threat-intelligence`, `tiger-eye`, `tiger-watch`.

### 2.2 Container View (C2)

```
+--tigerfetch binary (single process)----------------------------------------+
|                                                                            |
|  main.go (composition root)                                                |
|                                                                            |
|  +-----------+  +----------+  +----------+  +----------+  +-----------+   |
|  | HTTP      |  | Feed     |  | NVD      |  | KEV      |  | EPSS      |   |
|  | Server    |  | Ingestor |  | Runner   |  | Runner   |  | Runner    |   |
|  | :9101     |  | (5 slots)|  | (1h poll)|  | (24h)    |  | (24h)     |   |
|  +-----------+  +----------+  +----------+  +----------+  +-----------+   |
|                                                                            |
|  +-----------+  +----------+  +----------+  +----------+  +-----------+   |
|  | OSV       |  | GHSA     |  | URLhaus  |  | ThreatFox|  | Malware-  |   |
|  | Runner    |  | Runner   |  | Runner   |  | Runner   |  | Bazaar    |   |
|  | (24h,     |  | (1h,     |  | (1h)     |  | (1h)     |  | (1h)      |   |
|  | per-eco)  |  | cursor)  |  |          |  |          |  |           |   |
|  +-----------+  +----------+  +----------+  +----------+  +-----------+   |
|                                                                            |
|  +-----------+  +----------+  +-----------------------------------------+ |
|  | Nuclei    |  | MSF      |  | Alerting (sleeper-CVE detect + webhook) | |
|  | Runner    |  | Runner   |  | (configurable cadence; cursor-deduped)  | |
|  | (24h)     |  | (24h)    |  |                                         | |
|  +-----------+  +----------+  +-----------------------------------------+ |
|                                                                            |
|  +-----------------------------------------------------------------------+ |
|  |                    pgxpool (max 25 conns)                             | |
|  +-----------------------------------------------------------------------+ |
+----------------------------------------------------------------------------+
```

### 2.3 Component View (C3)

```
cmd/tigerfetch/
  main.go                    Composition root, signal handling, goroutine lifecycle

internal/
  config/config.go           Viper-based TOML + env var configuration
  db/db.go                   pgxpool creation, Goose migrations
  ingestor/ingestor.go       RSS/Atom fetch, parse, sanitise, upsert
  cve/nvd.go                 NVD v2.0 API: paginated fetch, 120-day windows, retry
  cve/kev.go                 CISA KEV: typed table sync with knownRansomwareUse + cwes[]
  cve/epss.go                FIRST EPSS: paginated CSV, COPY FROM bulk load
                             + materialize_epss_to_cve_enriched() callout
  osv/osv.go                 OSV per-ecosystem ZIP bundles (PyPI/npm/Go/...)
  ghsa/ghsa.go               GitHub Security Advisory REST API + Link pagination
  abusech/urlhaus.go         abuse.ch URLhaus CSV feed
  abusech/threatfox.go       abuse.ch ThreatFox JSON API (Auth-Key)
  abusech/malwarebazaar.go   abuse.ch MalwareBazaar JSON API (Auth-Key)
  nuclei/nuclei.go           ProjectDiscovery template tarball stream-walker
  msf/msf.go                 Rapid7 modules_metadata_base.json cache reader
  alerting/                  Sleeper-CVE detector + Slack Block Kit / generic webhook
                             senders, cursor-deduped via ingest_state
  metrics/metrics.go         60+ Prometheus metric definitions (promauto)
  metrics/middleware.go      HTTP request/duration instrumentation
  metrics/dbcollector.go     Live pgxpool.Stat() collector

migrations/                  ~20 SQL files, Goose-managed, embedded at build time
                             (see Appendix A for the full list)
```

---

## 3. Data Model

### 3.1 Lake shape (post-2026-05 migration)

The data lake has three tiers, with TigerFetch writing only the first:

```
+------------- Tier 1: ingested (tigerfetch writes) ------------------+
| archive / current             RSS/Atom articles                      |
| cve_enriched                  NVD CVE detail                         |
| cve_kev                       CISA KEV (first-class table)           |
| cve_enriched_history          Append-only change-log on cve_enriched |
| epss_daily (partitioned)      EPSS daily snapshots                   |
| osv_vulns                     OSV per-ecosystem advisories           |
| ghsa_advisories               GitHub Security Advisory Database      |
| urlhaus_urls                  abuse.ch URLhaus URLs                  |
| threatfox_iocs                abuse.ch ThreatFox IOCs                |
| malwarebazaar_samples         abuse.ch MalwareBazaar samples         |
| nuclei_templates              ProjectDiscovery exploit templates     |
| msf_modules                   Metasploit module metadata             |
| ingest_state                  Per-source cursor tracking             |
+---------------------------------------------------------------------+
              |
              v
+------------- Tier 2: enriched (tiger-eye writes) -------------------+
| analysis                      LLM-enriched per-article verdict       |
| analysis_embedding (vector)   1536-dim pgvector embeddings           |
| threat_actors / analysis_actor    Canonicalised actor entities      |
| malware_families / analysis_malware    Canonicalised family entities|
| pipeline_runs                 Per-enrichment-cycle cost + latency    |
+---------------------------------------------------------------------+
              |
              v
+------------- Tier 3: applied (tiger-watch + o2 + analysts) ---------+
| sbom_documents / sbom_packages    Customer SBOM inventory           |
| watchlist_matches             SBOM × OSV/GHSA matches               |
| o2_users / o2_calls / o2_call_turns    Voice-agent state            |
+---------------------------------------------------------------------+

(legacy.*)  Historical schema restored from the May-2026 fly.io dump.
            Read-only. Used by the v_*_comparison views to spot-check
            model drift across the migration.
```

### 3.2 Tier-1 table semantics (TigerFetch's write surface)

| Table | Write pattern | Dedup strategy | Growth |
|---|---|---|---|
| `archive` | Append-only | `ON CONFLICT (guid, feed_url) DO NOTHING` | ~700 items/cycle |
| `current` | Last-write-wins | `ON CONFLICT (guid, feed_url) DO UPDATE` | bounded by unique items |
| `cve_enriched` | Upsert | `ON CONFLICT (cve_id, source) DO UPDATE` | ~350k (NVD); KEV moved to `cve_kev` |
| `cve_kev` | Upsert | `ON CONFLICT (cve_id) DO UPDATE`; `withdrawn_at` flag for catalog removals | ~1.6k active |
| `cve_enriched_history` | Insert (via trigger on `cve_enriched`) | One row per actual state-change (no no-op UPDATEs) | grows with NVD churn |
| `epss_daily` | Bulk load via `COPY FROM` | Date-existence check before run | ~300k/day, partitioned monthly |
| `osv_vulns` | Upsert | `WHERE modified IS DISTINCT FROM EXCLUDED.modified` | ~265k |
| `ghsa_advisories` | Upsert | `WHERE updated IS DISTINCT FROM EXCLUDED.updated` | ~335k |
| `urlhaus_urls` | Upsert | row only touched when `url_status`/`last_online` change | ~26k |
| `threatfox_iocs` | Upsert | `ioc_id` PK; same `IS DISTINCT FROM` guard | ~3.5k 7-day window |
| `malwarebazaar_samples` | Upsert | `sha256_hash` PK; idem | ~300 60-min window |
| `nuclei_templates` | Upsert | SHA-256 of YAML body is the change-detection key | ~5.6k |
| `msf_modules` | Upsert | `fullname` PK; row only touched on `raw IS DISTINCT FROM EXCLUDED.raw` | ~6.6k |
| `ingest_state` | Upsert | `ON CONFLICT (source) DO UPDATE` | ~10 rows total |

### 3.3 Indexes

Each new Tier-1 table follows the same shape:

- One PK on the natural identifier.
- A GIN index on every text array used for joins (`cves[]`, `package_names[]`, `aliases[]`, `tags[]`).
- A `partial btree` on `modified DESC WHERE withdrawn IS NULL` for "latest active" queries.
- A btree on each FK column.

Full per-table index inventory in [`docs/SOURCES-TIERED.md`](SOURCES-TIERED.md).

### 3.4 Views

The lake exposes ~25 views falling into three groups:

| Group | Examples | Purpose |
|---|---|---|
| Feed quality | `v_feed_coverage_summary`, `v_missing_both_per_feed`, `v_missing_both_by_day`, `v_percent_missing_both` | Operational visibility into RSS/Atom content gaps |
| Threat-intel rollups | `v_epss_movers_24h`, `v_top_threat_actors_30d`, `v_top_malware_families_30d`, `v_actor_malware_cooccurrence_90d`, `v_threat_actor_summary`, `v_malware_family_summary` | Analyst-facing rankings |
| Pipeline observability | `v_pipeline_runs_recent`, `v_pipeline_cost_per_day`, `v_pipeline_by_prompt_version` | Per-run cost + latency for tiger-eye |
| Migration audit | `v_actor_normalisation_demo`, `v_kev_demotion`, `v_analysis_comparison` | Side-by-side `legacy.*` vs `public.*` to spot-check the May-2026 cutover |

---

## 4. Data Sources & Ingestion Pipelines

The 11 ingestors fall into four shape classes:

| Shape | Cursor | Idempotency mechanism | Sources |
|---|---|---|---|
| Incremental API w/ time cursor | RFC3339 timestamp in `ingest_state` | `ON CONFLICT … WHERE … IS DISTINCT FROM …` | NVD, GHSA |
| Single-file catalogue | Catalogue version/date in `ingest_state` | Skip run if cursor unchanged | CISA KEV, MSF (Rapid7 JSON cache), Nuclei (tarball) |
| Per-window pull | "first_seen >= now() - N" implicit | PK conflict + row-changed guard | URLhaus, ThreatFox, MalwareBazaar |
| Bulk daily snapshot | Date in partition table | Skip if date already present | EPSS |
| Per-ecosystem bundle | none (re-fetch each cycle) | `WHERE modified IS DISTINCT FROM …` | OSV (per-ecosystem ZIPs) |

Per-pipeline detail below.

### 4.1 RSS/Atom Feed Pipeline

```
  22 Feeds          Ingestor              Sanitiser           PostgreSQL
  --------          --------              ---------           ----------
  RSS/Atom  --HTTP-->  gofeed.Parse()  -->  bluemonday   -->  archive (INSERT)
  XML               30s timeout            UGCPolicy()       current (UPSERT)
                    per feed               strips <script>,
                                           onclick, etc.
```

**Concurrency:** Semaphore-bounded at 5 concurrent fetches via buffered channel. `sync.WaitGroup` ensures all feeds complete before the next cycle.

**Polling:** Configurable via `ingest_interval` (default: 1 hour).

**Field Resolution:**
- `guid`: `item.GUID` or falls back to `item.Link`
- `published`: `item.PublishedParsed` or `item.UpdatedParsed`
- `author`: first author's `Name` field
- `content`/`summary`: HTML-sanitised via bluemonday UGC policy

**Items without a GUID or Link are silently skipped** (logged at ERROR level).

### 4.2 NVD Pipeline (CVE Enrichment)

```
  NVD API v2.0      NvdRunner             Batch Save         PostgreSQL
  ------------      ---------             ----------         ----------
  Paginated   ---->  120-day windows  -->  pgx.Batch()  -->  cve_enriched
  JSON               2000 results/page     Extract CVSS      (source='NVD')
                     cursor in             V3.1 > V3.0
                     ingest_state          base score
```

**Window Strategy:** NVD limits queries to 120-day ranges. The runner splits the gap between the cursor and now into sequential 120-day windows, advancing the cursor after each.

**Rate Limiting:**
| Mode | Rate | Delay Between Pages |
|------|------|-------------------|
| Without API key | 5 req/30s | 6 seconds |
| With API key | 50 req/30s | 600ms |

**Retry Logic:** Exponential backoff on HTTP 429/503. Initial: 6s, doubles per retry, capped at 60s.

**Polling:** Configurable via `nvd.poll_interval` (default: 1 hour).

### 4.3 KEV Pipeline (Known Exploited Vulnerabilities)

```
  CISA JSON          KevRunner             Batch Upsert       PostgreSQL
  ---------          ---------             ------------       ----------
  Single file  --->  Compare catalog  -->  pgx.Batch()   -->  cve_enriched
  (~1.2k vulns)      version to cursor     Marshal each       (source='CISA-KEV')
                     Skip if unchanged     vuln to JSON
```

**Idempotency:** Compares `CatalogVersion` or `DateReleased` against stored cursor. If unchanged, the entire run is skipped (`status="up_to_date"`).

**Polling:** Default 24 hours.

### 4.4 EPSS Pipeline (Exploit Prediction Scoring)

```
  FIRST.org API      EpssRunner            COPY FROM          PostgreSQL
  -------------      ----------            ---------          ----------
  Paginated    --->  Check if date   --->  pgx.CopyFrom()  -> epss_daily
  CSV/JSON           already ingested      ~300k rows/day     (partitioned)
  5000/page          Auto-create monthly                      by month
                     partition
```

**Partition Auto-Creation:** Before each bulk load, ensures the target monthly partition exists:
```sql
CREATE TABLE IF NOT EXISTS epss_daily_y2026m03
PARTITION OF epss_daily
FOR VALUES FROM ('2026-03-01') TO ('2026-04-01')
```

**Bulk Performance:** Uses PostgreSQL `COPY FROM` protocol via `pgx.CopyFrom()` for high-throughput loading (~300k records per daily snapshot).

**Polling:** Default 24 hours. Skips entirely if today's date already exists.

**Materialisation back to `cve_enriched`:** Migration `20260516_materialize_epss_to_cve_enriched.sql` introduced a PL/pgSQL function `materialize_epss_to_cve_enriched()` that pulls the latest score per CVE from the `epss_daily` partitions and writes it to `cve_enriched.epss`. Idempotent (only updates rows whose score actually changed). Coverage went from 0 % → 95 % on first run.

### 4.5 OSV Pipeline (per-ecosystem bundles)

```
  osv-vulnerabilities.storage.googleapis.com    OsvRunner            PostgreSQL
  -------------------------------------------    ---------            ----------
  <eco>/all.zip   (PyPI, npm, Go, Maven, ...)  --> unzip in-memory --> osv_vulns
                  one ZIP per ecosystem             walk each .json      (upsert,
                  Default: 11 ecosystems            extract aliases,     IS DISTINCT
                                                    affected ranges      FROM guard)
```

**Idempotency:** `WHERE modified IS DISTINCT FROM EXCLUDED.modified` means re-fetch with no upstream changes touches 0 rows. Each ecosystem cursors independently.

**Range filtering:** The denormalised `affected` column carries the package identity only; the original `raw.affected` jsonb has the `ranges` + `versions` arrays needed for proper version-range evaluation (done in tiger-watch's Python comparator, not here).

**Known limitation:** `cvss_v3` is NULL for advisories that publish only the CVSS vector (most GHSA-sourced PyPI entries). Adding a CVSS-vector evaluator is a follow-up.

### 4.6 GHSA Pipeline (incremental w/ Link pagination)

```
  api.github.com/advisories         GhsaRunner            PostgreSQL
  ---------------------------       ----------            ----------
  ?modified=>{cursor}         --->  Follow Link:rel=next  --> ghsa_advisories
  Anonymous: 60 req/h               Persist cursor on        (upsert, withdrawn
  With token: 5,000 req/h           every page so a          flag preserved)
                                    rate-limit mid-stream
                                    doesn't replay
```

**Cursor:** ISO-8601 `modified` of the last advisory in the last successful page. Stored as `ingest_state(source='GHSA')`.

**Auth:** `cfg.GHSA.Token` (env `GHSA_TOKEN`) — required for the initial ~30K-advisory backfill; optional thereafter.

### 4.7 abuse.ch Pipeline (URLhaus / ThreatFox / MalwareBazaar)

```
  urlhaus.abuse.ch/downloads/csv_recent/        UrlhausRunner       urlhaus_urls
  threatfox-api.abuse.ch/api/v1/                ThreatfoxRunner --> threatfox_iocs
  mb-api.abuse.ch/api/v1/                       MalwarebazaarRunner malwarebazaar_samples

  All three share a single ABUSECH_API_KEY (Auth-Key header). URLhaus
  switched from key-less to authenticated alongside the other two in 2024.
```

**Idempotency:** PK on `id` / `ioc_id` / `sha256_hash` respectively, with the `row only updated when something meaningful changed` guard (`url_status`/`last_online` for URLhaus; full row for the other two via `IS DISTINCT FROM`).

**Polling:** All three at 1h cadence. ThreatFox requests `query=get_iocs days=7`; MalwareBazaar `selector=time` (60-min window). URLhaus pulls the recent-CSV file each cycle.

**Failure mode:** Each runner short-circuits cleanly when `ABUSECH_API_KEY` is unset, so the rest of the binary still works in environments without the secret.

### 4.8 Nuclei Pipeline (tarball stream-walker)

```
  github.com/projectdiscovery/nuclei-templates  NucleiRunner
  ------------------------------------------    ------------
  /archive/refs/heads/main.tar.gz       --->    Stream-walk the tar  --> nuclei_templates
                                                in-memory; parse every    (idempotent on
                                                YAML under configured     yaml_sha256)
                                                subdirs (http/cves,
                                                http/vulnerabilities,
                                                network/cves, ...)
```

**CVE extraction:** Collects refs from three sources — `classification.cve-id`, `tags`, template `id`. Deduped uppercase.

**Quirks handled:** YAML fields can be scalar *or* sequence (`author`, `tags`, `cve-id`, `cwe-id`); literal `0x00` bytes in payload examples are stripped before insert.

### 4.9 MSF Pipeline (Rapid7 JSON cache)

```
  raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json
  ----------------------------------------------------------------------------------------
  Single ~10 MB JSON file              MsfRunner             msf_modules
  with every module's metadata  --->   Parse + extract  -->  (upsert, raw IS
  already structured                   CVE refs from         DISTINCT FROM guard)
                                       refs[] (skip
                                       OSVDB / URL / EDB)
```

**Why this and not the Ruby ecosystem:** Rapid7 publishes the cache for exactly this consumption pattern. No Ruby toolchain needed.

**Rank label:** Mapped from the numeric `rank` field — `manual / low / average / normal / good / great / excellent`. `excellent + great` is the conventional "weaponised" threshold (~1,664 modules currently).

### 4.10 Sleeper-CVE Alerting

```
  cve_enriched + epss_daily    Alerter              Slack Block Kit / Generic JSON
  -------------------------    -------              -------------------------------
  Look up each CVE's      -->  Detect: was <X%      -->  Webhook POST
  EPSS at (now - lookback)     in past, >=Y% now;        (cursor-deduped via
  and at (now)                 emit notification         ingest_state to prevent
                               with NVD link,            duplicate alerts)
                               coloured CVSS badge,
                               CWE, truncated desc
```

**Default thresholds:** baseline < 10 %, current ≥ 50 %. Configurable.

**Block-Kit cap:** 10 CVEs per Slack message (Slack block limit) — overflow noted in trailer.

---

## 5. Concurrency Model

### 5.1 Goroutine Map

```
main goroutine
  |
  +-- HTTP server (ListenAndServe)
  |
  +-- NVD runner loop
  |     for { Run(); select { ctx.Done | time.After(1h) } }
  |
  +-- KEV runner loop
  |     for { Run(); select { ctx.Done | time.After(24h) } }
  |
  +-- EPSS runner loop
  |     for { Run(); select { ctx.Done | time.After(24h) } }
  |
  +-- Feed ingestor loop
  |     sem := make(chan struct{}, 5)  // bounded concurrency
  |     for {
  |       for each feed:
  |         sem <- struct{}{}          // acquire slot
  |         go func() {
  |           defer { <-sem }          // release slot
  |           FetchAndSave()
  |         }
  |       wg.Wait()
  |       select { ctx.Done | time.After(1h) }
  |     }
  |
  +-- signal.Notify(SIGINT, SIGTERM)
        cancel() -> all goroutines exit via ctx.Done
        server.Shutdown(10s timeout)
```

### 5.2 Shared Resources

| Resource | Access Pattern | Protection |
|----------|---------------|------------|
| `pgxpool.Pool` | All goroutines | Connection pool (max 25, internally thread-safe) |
| Prometheus registry | All goroutines | `promauto` uses atomic operations |
| Context | All goroutines | Read-only after creation; cancel propagates shutdown |

### 5.3 Graceful Shutdown Sequence

```
SIGTERM received
  1. cancel() called on root context
  2. All worker loops detect ctx.Done in their select{} and return
  3. server.Shutdown(10s) drains in-flight HTTP requests
  4. pool.Close() releases database connections
  5. Process exits
```

---

## 6. Configuration

### 6.1 Configuration Sources (Priority Order)

```
1. Environment variables     DATABASE_URL, LOG_LEVEL, NVD_API_KEY
2. Config.toml file          ./Config.toml, /etc/tigerfetch/, ~/.tigerfetch/
3. Defaults                  server_bind=0.0.0.0:9101, ingest_interval=1h
```

### 6.2 Configuration Schema

```toml
# Required
database_url    = "postgres://user:pass@host:5432/tiger2go?sslmode=disable"

# Optional (with defaults)
ingest_interval = "1h"
server_bind     = "0.0.0.0:9101"

[nvd]
enabled         = true
poll_interval   = "1h"
page_size       = 2000
api_key         = ""               # NVD_API_KEY env override; 5 → 50 req/30s

[kev]
enabled         = true
poll_interval   = "24h"
url             = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

[epss]
enabled         = true
poll_interval   = "24h"
page_size       = 5000

[osv]
enabled         = true
poll_interval   = "24h"
ecosystems      = ["PyPI", "npm", "Go", "Maven", "RubyGems",
                   "crates.io", "Packagist", "NuGet", "Pub",
                   "Hex", "Hackage"]

[ghsa]
enabled         = true
poll_interval   = "1h"
token           = ""               # GHSA_TOKEN env override

[urlhaus]
enabled         = true
poll_interval   = "1h"
# auth_key picked up from ABUSECH_API_KEY

[threatfox]
enabled         = true
poll_interval   = "1h"
# auth_key picked up from ABUSECH_API_KEY

[malwarebazaar]
enabled         = true
poll_interval   = "1h"
# auth_key picked up from ABUSECH_API_KEY

[nuclei]
enabled         = true
poll_interval   = "24h"
template_subdirs = ["http/cves/", "http/vulnerabilities/",
                    "dns/", "network/cves/", "file/",
                    "javascript/cves/", "ssl/"]

[msf]
enabled         = true
poll_interval   = "24h"

[alerting]
enabled         = true
[[alerting.webhooks]]
name            = "soc"
type            = "slack"
url             = "https://hooks.slack.com/services/..."

[[feeds]]
name            = "CISA Cybersecurity Alerts"
url             = "https://us-cert.cisa.gov/ncas/alerts.xml"
feed_type       = "official"
tags            = ["government", "alerts"]
```

### 6.3 Environment Variables

| Variable | Maps to | Required |
|---|---|---|
| `DATABASE_URL` | `database_url` | Yes |
| `LOG_LEVEL` | slog level | No (default: INFO) |
| `NVD_API_KEY` | `nvd.api_key` | No (10× rate limit if set) |
| `GHSA_TOKEN` | `ghsa.token` | No (60 → 5,000 req/h if set) |
| `ABUSECH_API_KEY` | `urlhaus.auth_key`, `threatfox.auth_key`, `malwarebazaar.auth_key` | Required to enable the abuse.ch trio |
| `SERVER_BIND` | `server_bind` | No |
| `INGEST_INTERVAL` | `ingest_interval` | No |

---

## 7. Observability

### 7.1 Metrics (Prometheus)

**60+ metrics exposed at `GET /metrics` with prefix `tigerfetch_`.** New ingestors follow the same `{ingestor}_fetches_total{status}` + `{ingestor}_records_processed_total` + `{ingestor}_run_duration_seconds` triplet, listed below.

#### Feed Ingestion Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `feed_fetches_total` | Counter | feed_name, status | Fetch attempts (success/error) |
| `feed_items_processed_total` | Counter | feed_name | Items parsed per feed |
| `feed_items_new_total` | Counter | feed_name | New items inserted into archive |
| `feed_items_updated_total` | Counter | feed_name | Items updated in current |
| `feed_items_failed_total` | Counter | feed_name | Items that failed processing |
| `feed_items_empty_content_total` | Counter | feed_name | Items with no content or summary |
| `feed_fetch_duration_seconds` | Histogram | feed_name | End-to-end fetch+process time |
| `feed_last_success_timestamp` | Gauge | feed_name | Unix timestamp of last success |

#### CVE Enrichment Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nvd_fetches_total` | Counter | status | NVD API call outcomes |
| `nvd_cves_processed_total` | Counter | — | CVEs saved to DB |
| `nvd_cves_without_cvss_total` | Counter | — | CVEs missing CVSS scores |
| `nvd_batch_size` | Histogram | — | Items per API page |
| `nvd_rate_limits_total` | Counter | — | HTTP 429/503 responses |
| `nvd_api_errors_total` | Counter | status_code | Non-retryable API errors |
| `nvd_run_duration_seconds` | Histogram | — | Full run wall time |
| `nvd_cursor_lag_seconds` | Gauge | — | Seconds behind real-time |
| `kev_fetches_total` | Counter | status | KEV fetch outcomes |
| `kev_vulns_processed_total` | Counter | — | KEV vulns upserted |
| `kev_run_duration_seconds` | Histogram | — | Full run wall time |
| `kev_cursor_lag_seconds` | Gauge | — | Seconds behind latest catalog |
| `epss_runs_total` | Counter | status | EPSS run outcomes (success/error/skipped) |
| `epss_records_processed_total` | Counter | — | EPSS records bulk-loaded |
| `epss_pages_fetched_total` | Counter | — | API pages retrieved |
| `epss_run_duration_seconds` | Histogram | — | Full run wall time |
| `epss_cursor_lag_seconds` | Gauge | — | Seconds behind latest date |

#### Tier-1 source metrics (new in v1.4.0)

Every new ingestor follows the same triplet — fetches counter with status label, records-processed counter, and run-duration histogram.

| Source | Metrics |
|---|---|
| OSV | `osv_fetches_total{ecosystem,status}`, `osv_vulns_processed_total{ecosystem}`, `osv_run_duration_seconds` |
| GHSA | `ghsa_fetches_total{status}`, `ghsa_advisories_processed_total`, `ghsa_pages_fetched_total`, `ghsa_run_duration_seconds`, `ghsa_rate_limit_remaining` |
| URLhaus | `urlhaus_fetches_total{status}`, `urlhaus_rows_processed_total`, `urlhaus_run_duration_seconds` |
| ThreatFox | `threatfox_fetches_total{status}`, `threatfox_iocs_processed_total`, `threatfox_run_duration_seconds` |
| MalwareBazaar | `malwarebazaar_fetches_total{status}`, `malwarebazaar_samples_processed_total`, `malwarebazaar_run_duration_seconds` |
| Nuclei | `nuclei_fetches_total{status}`, `nuclei_templates_processed_total`, `nuclei_run_duration_seconds` |
| MSF | `msf_fetches_total{status}`, `msf_modules_processed_total`, `msf_run_duration_seconds` |
| Alerting | `alerting_runs_total{status}`, `sleeper_cves_detected_total`, `webhooks_sent_total{webhook,outcome}`, `alerting_run_duration_seconds` |

#### Infrastructure Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `upstream_request_duration_seconds` | Histogram | source | HTTP latency by source (feed/nvd/kev/epss) |
| `http_requests_total` | Counter | path, status_code | Inbound HTTP requests |
| `http_request_duration_seconds` | Histogram | path | Inbound request latency |
| `db_pool_total_conns` | Gauge | — | Total pool connections |
| `db_pool_idle_conns` | Gauge | — | Idle connections |
| `db_pool_acquired_conns` | Gauge | — | In-use connections |
| `db_pool_max_conns` | Gauge | — | Pool maximum (25) |
| `db_pool_constructing_conns` | Gauge | — | Connections being established |
| `db_pool_acquire_count_total` | Counter | — | Lifetime connection acquisitions |
| `db_pool_acquire_duration_seconds_total` | Counter | — | Cumulative acquire wait time |
| `db_pool_empty_acquire_total` | Counter | — | Pool exhaustion events |
| `build_info` | Gauge | version, go_version, commit | Always 1; carries build metadata |
| `start_time_seconds` | Gauge | — | Process start Unix timestamp |

### 7.2 Key Dashboard Queries

```promql
# Feed health: success rate over 1 hour
sum(rate(tigerfetch_feed_fetches_total{status="success"}[1h]))
/ sum(rate(tigerfetch_feed_fetches_total[1h]))

# NVD catch-up progress
tigerfetch_nvd_cursor_lag_seconds

# Feed freshness: time since last successful fetch
time() - tigerfetch_feed_last_success_timestamp

# Database pool saturation
tigerfetch_db_pool_acquired_conns / tigerfetch_db_pool_max_conns

# EPSS bulk load throughput
rate(tigerfetch_epss_records_processed_total[1h])

# Upstream latency P99 by source
histogram_quantile(0.99, rate(tigerfetch_upstream_request_duration_seconds_bucket[5m]))
```

### 7.3 Recommended Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Feed stale | `time() - tigerfetch_feed_last_success_timestamp > 7200` | Warning |
| NVD falling behind | `tigerfetch_nvd_cursor_lag_seconds > 86400` | Warning |
| EPSS missed day | `tigerfetch_epss_cursor_lag_seconds > 172800` | Warning |
| Pool exhaustion | `tigerfetch_db_pool_empty_acquire_total` increasing | Critical |
| NVD rate limited | `rate(tigerfetch_nvd_rate_limits_total[5m]) > 0` | Info |
| Feed errors | `rate(tigerfetch_feed_fetches_total{status="error"}[15m]) > 0.5` | Warning |

### 7.4 Structured Logging

All logging uses Go's `log/slog` with structured key-value pairs:

```
level=INFO msg="Fetched feed success" title="CISA Alerts" items=10 url="https://..."
level=ERROR msg="Feed ingestion error" feed="Broken Feed" error="connection refused"
level=WARN msg="Invalid poll interval, using default 1h" error="invalid duration"
```

Configurable via `LOG_LEVEL` environment variable: `DEBUG`, `INFO`, `WARN`, `ERROR`.

### 7.5 HTTP Endpoints

| Endpoint | Method | Purpose | Auth |
|----------|--------|---------|------|
| `/healthz` | GET | Liveness probe (returns `200 OK`) | None |
| `/metrics` | GET | Prometheus scrape endpoint | None |

### 7.6 Grafana Dashboards

Four provisioned dashboards auto-load via `grafana/dashboards/` and require zero manual setup.

#### `tigerfetch-overview` (Prometheus)

Operational dashboard for the tigerfetch binary itself.

| Row | Purpose |
|---|---|
| System Overview | Uptime, Go version, goroutines, memory, GC pause |
| Feed Ingestion | Success rate, items/min, empty content ratio, freshness, per-feed breakdown |
| NVD Enrichment | Fetch rate, CVEs processed, cursor lag, batch size, run duration |
| EPSS & KEV | EPSS records, run outcomes, KEV vuln count, cursor lag |
| **Tier-1 Threat-Intel Sources** | OSV / GHSA / URLhaus / ThreatFox / MalwareBazaar / Nuclei / MSF — records processed, success/error rate, p95 run duration |
| Sleeper-CVE Alerting | Runs, detected CVEs, webhook outcomes |
| Upstream HTTP | Latency heatmap, P50/P99 by source, error rate |
| DB Pool | Utilisation gauge, connection breakdown, acquire latency, exhaustion events |
| Runtime | Goroutine count, heap usage, GC frequency |

#### `threat-intelligence` (PostgreSQL)

Analytical dashboard sourced from the lake.

| Row | Purpose |
|---|---|
| Threat Landscape Overview | Total CVEs, KEV entries, critical CVEs, EPSS records, high-risk count, feed items (7d) |
| EPSS — Exploit Prediction | Top 25 most exploitable CVEs, biggest 24h movers, score distribution, daily record trend |
| Danger Zone — CVSS × EPSS | Combined: CVEs with high severity AND high exploit probability, risk score, KEV flag |
| NVD — Vulnerability Landscape | CVSS distribution, CVEs by severity over time, latest critical CVEs |
| Tier-1 Source Volume | OSV / GHSA / URLhaus / ThreatFox / MalwareBazaar / Nuclei / MSF row counts + growth |
| SBOM Coverage | (tiger-watch lake) advisories per service, advisories ranked by severity |
| Feed Intelligence | Feed volume timeline, content coverage by feed, latest 50 feed items with links |

Risk-score formula: `ROUND((cvss_base * epss * 10) / 10, 2)` — 0–10 scale combining severity with exploitation likelihood.

#### `tiger-eye` (Prometheus + PostgreSQL)

Companion dashboard for the Python enrichment pipeline. Analysis volume, DLQ depth (retryable + exhausted), model cost per day, per-prompt-version cost, p95 LLM latency, embedding coverage.

#### `tiger-watch` (Prometheus + PostgreSQL)

Companion dashboard for the SBOM matching service. SBOM packages, advisories per service, version-range eval throughput, the "would have been a false positive without range filter" delta.

#### Datasource configuration

Both datasources are provisioned via `grafana/provisioning/datasources/datasource.yml`:

| Datasource | Type | UID | Target | Default |
|---|---|---|---|---|
| Prometheus | `prometheus` | `prometheus` | `http://prometheus:9090` | Yes |
| PostgreSQL | `postgres` | `pg` | `db:5432` | No |

#### Prometheus scrape jobs

Three jobs are configured (`prometheus.yml`):

| Job | Target | Notes |
|---|---|---|
| `tigerfetch` | `tigerfetch:9101` | This binary |
| `tiger-eye` | `tiger-eye:8080` | Python enrichment |
| `tiger-watch` | `tiger-watch:8081` | Python SBOM service |

---

## 8. Security

### 8.1 Input Sanitisation

| Vector | Mitigation |
|--------|-----------|
| RSS/Atom content (XSS) | `bluemonday.UGCPolicy()` strips `<script>`, `onclick`, `javascript:` URIs |
| SQL injection | 100% parameterised queries (`$1, $2, ...`) throughout |
| Feed URLs | Sourced from operator-controlled `Config.toml`, not user input |

### 8.2 Secret Management

| Secret | Storage | Notes |
|--------|---------|-------|
| `DATABASE_URL` | Environment variable | Contains credentials |
| `NVD_API_KEY` | Config.toml or env var | Optional; rate limit improvement |
| `Config.toml` | `.gitignore` + `.dockerignore` | Never in image or repo |

### 8.3 Container Hardening

- **Non-root user:** `app:app` created at build time
- **Minimal base image:** `debian:bookworm-slim` (no shell utilities)
- **No secrets in image:** Config.toml excluded via `.dockerignore`
- **CA certificates only:** Single `apt-get install ca-certificates`
- **Trivy scanned:** CI blocks on HIGH/CRITICAL CVEs

### 8.4 CI Security Gates

| Gate | Tool | Stage |
|------|------|-------|
| SAST | gosec | Job 2: Security Scans |
| SCA (dependencies) | govulncheck | Job 2: Security Scans |
| Container CVEs | Trivy | Job 4: Container Scan |
| Race detection | `go test -race` | Job 3: Tests |

---

## 9. Deployment

### 9.1 Build Pipeline

```
git push
  |
  v
GitHub Actions CI (4 jobs)
  |
  +-- Job 1: Code Quality (gofmt + golangci-lint)
  +-- Job 2: Security Scans (govulncheck + gosec)
  +-- Job 3: Tests (go test -race -cover + Postgres service)
  |
  +-- Job 4: Container Scan (docker build + Trivy)
       [only runs if Jobs 1-3 pass]
```

### 9.2 Local Development

```bash
# Start database
docker compose up db -d

# Run with hot reload
DATABASE_URL="postgres://user:pass@localhost:5432/tiger2go" go run ./cmd/tigerfetch

# Full stack
docker compose up --build
```

### 9.3 Production (Fly.io)

```
Region:     Amsterdam (ams)
CPU:        1x shared
Memory:     512 MB
Scaling:    Always-on (min_machines_running=1)
HTTPS:      Enforced (force_https=true)
Port:       9101 (internal)
```

### 9.4 Docker Compose Stack

```
+-----------+     +-----------+     +------------+     +-----------+
| postgres  |<----| tigerfetch|---->| prometheus |---->| grafana   |
| :5432     |     | :9101     |     | :9090      |     | :3000     |
| (PG 16)   |     | (Go app)  |     | (scrapes   |     | (2 dash-  |
+-----------+     +-----------+     |  every 15s)|     |  boards)  |
     |                              +------------+     +-----------+
     |                                                       |
     +-------------------------------------------------------+
     |                          (SQL queries for Threat Intel dashboard)
     v
 tiger2go_data
 (named volume)
```

Services: `db`, `tigerfetch`, `prometheus`, `grafana`. All on `tiger2go_net` bridge network.

---

## 10. Connection Pool Configuration

```go
MaxConns:          25           // Maximum total connections
MinConns:           2           // Minimum idle connections
MaxConnLifetime:   1h           // Recycle connections after 1 hour
MaxConnIdleTime:  30m           // Close idle connections after 30 minutes
```

**Pool Sizing Rationale:** Peak concurrency is 5 feed fetches + 3 CVE runners + 1 HTTP server = 9 concurrent DB consumers. With 25 max connections, the pool has ~2.7x headroom for burst queries within each runner (batch inserts, cursor updates).

---

## 11. Error Handling & Resilience

### 11.1 Retry Matrix

| Source | Trigger | Strategy | Max Backoff |
|--------|---------|----------|-------------|
| NVD API | HTTP 429, 503 | Exponential backoff (6s base, 2x) | 60 seconds |
| NVD API | Other HTTP errors | Return error, retry next poll cycle | — |
| KEV | Catalog unchanged | Skip run (`status="up_to_date"`) | — |
| EPSS | Date already ingested | Skip run (`status="skipped"`) | — |
| Feeds | HTTP error | Return error, log, continue other feeds | — |
| Feeds | Missing GUID | Skip item, log at ERROR | — |
| DB | Transaction error | Rollback via deferred `tx.Rollback()` | — |

### 11.2 Failure Isolation

Each data source goroutine is fully independent:

- A failing feed does not block other feeds (errors logged, loop continues)
- A failing NVD run does not affect KEV, EPSS, or feed ingestion
- A panic in any goroutine would crash the process (no recover) — by design, this is preferred over silent corruption

### 11.3 Idempotency Guarantees

| Source | Mechanism | Guarantee |
|--------|-----------|-----------|
| Feeds | `ON CONFLICT (guid, feed_url) DO NOTHING` on archive | Same item never duplicated |
| Feeds | `ON CONFLICT (guid, feed_url) DO UPDATE` on current | Latest version always wins |
| NVD | Cursor in `ingest_state` + `ON CONFLICT` on cve_enriched | Re-processing is safe |
| KEV | Catalog version comparison before processing | Unchanged catalog skipped |
| EPSS | Date existence check in `epss_daily` | Same day never re-loaded |

---

## 12. Feed Inventory

### 12.1 Active Sources (22 RSS/Atom + 3 APIs)

| # | Source | Type | Category | Polling |
|---|--------|------|----------|---------|
| 1 | CISA Cybersecurity Alerts | RSS | Government | 1h |
| 2 | CISA Vulnerability Advisories | RSS | Government | 1h |
| 3 | UK NCSC Updates | RSS | Government | 1h |
| 4 | JPCERT Vulnerability Notes | RDF | Government | 1h |
| 5 | CERT-EU Security Advisories | RSS | Government | 1h |
| 6 | Debian Security List | RSS | Vendor | 1h |
| 7 | Cisco Security Advisories | RSS | Vendor | 1h |
| 8 | Ubuntu Security Notices | RSS | Vendor | 1h |
| 9 | SANS ISC Diaries | RSS | Community | 1h |
| 10 | MISP Project Blog | Atom | Community | 1h |
| 11 | Cisco Talos Intelligence | RSS | Analysis | 1h |
| 12 | Recorded Future Cyber Daily | RSS | Analysis | 1h |
| 13 | Palo Alto Unit42 | RSS | Analysis | 1h |
| 14 | Krebs on Security | RSS | Journalism | 1h |
| 15 | The DFIR Report | RSS | DFIR | 1h |
| 16 | BleepingComputer | RSS | News | 1h |
| 17 | The Hacker News | RSS | News | 1h |
| 18 | SecurityWeek | RSS | News | 1h |
| 19 | DarkReading | RSS | News | 1h |
| 20 | Google TAG Blog | RSS | Research | 1h |
| 21 | Google Project Zero | Atom | Research | 1h |
| 22 | Exploit-DB | RSS | Exploits | 1h |
| 23 | NVD (NIST) | JSON API | CVE Enrichment | 1h |
| 24 | CISA KEV | JSON | CVE Enrichment | 24h |
| 25 | FIRST EPSS | JSON API | CVE Scoring | 24h |

### 12.2 Disabled Sources (13)

Disabled due to upstream issues (404s, certificate mismatches, rate limiting, non-standard formats). Documented in `Config.toml` with explanations.

---

## 13. Dependencies

### 13.1 Direct Dependencies

| Package | Purpose |
|---|---|
| `jackc/pgx/v5` | PostgreSQL driver with connection pooling |
| `microcosm-cc/bluemonday` | HTML sanitisation (XSS prevention) |
| `mmcdole/gofeed` | RSS/Atom feed parsing |
| `pressly/goose/v3` | Database migration management |
| `prometheus/client_golang` | Prometheus metrics instrumentation |
| `spf13/viper` | Configuration management (TOML + env) |
| `gopkg.in/yaml.v3` | Nuclei template parsing |
| `stretchr/testify` | Test assertions |

Exact pinned versions live in `go.mod`.

### 13.2 Go Toolchain

```
go 1.26.0, toolchain go1.26.1
```

---

## 14. Testing Strategy

### 14.1 Test Matrix

| Package | Test Type | DB Required | Coverage |
|---------|-----------|-------------|----------|
| `internal/ingestor` | Integration | Yes | 89.6% |
| `internal/cve` | Integration | Yes | 71.2% |
| `cmd/tigerfetch` | — | — | 0% (composition root) |
| `internal/config` | — | — | 0% |
| `internal/metrics` | — | — | 0% |

### 14.2 Test Cases

| Test | Validates |
|------|----------|
| `TestFetchAndSave_Integration` | Happy path + idempotency (re-ingest produces no duplicates) |
| `TestFetchAndSave_EmptyContent` | Items with no content/summary still saved |
| `TestFetchAndSave_NoGUID` | Items without guid or link are skipped gracefully |
| `TestFetchAndSave_XSSSanitization` | `<script>` tags stripped by bluemonday |
| `TestFetchAndSave_HTTPError` | Upstream 500 returns descriptive error |
| `TestNvdRunner_Integration` | Full workflow: fetch, parse, save, cursor advance |
| `TestKevRunner_Integration` | Catalog sync, version comparison, state persistence |
| `TestEpssRunner_Integration` | Pagination, partition creation, bulk COPY FROM |

### 14.3 CI Test Infrastructure

- **Database:** Postgres 15-alpine service container with health checks
- **Race detector:** `go test -race` enabled on all test runs
- **Coverage:** Reported but no threshold enforced

---

## 15. Capacity & Scaling

### 15.1 Current Throughput

| Dimension | Value |
|---|---|
| RSS/Atom feeds | 22 sources, ~700 items per cycle |
| NVD CVEs | ~351k (120-day sliding window of `cve_enriched`) |
| CISA KEV | ~1,590 active in `cve_kev` |
| EPSS records | ~300k per daily snapshot; ~11M across `epss_daily_y2026m*` partitions |
| OSV advisories | ~264k across 11 ecosystems |
| GHSA advisories | ~333k |
| URLhaus URLs | ~25k (2.1k currently online) |
| ThreatFox IOCs | ~3.5k (7-day rolling window) |
| MalwareBazaar samples | ~300 (60-min rolling window) |
| Nuclei templates | ~5.6k (1.6k critical-severity) |
| MSF modules | ~6.6k (1.6k excellent/great rank) |
| DB connections | Max 25 (typical: 8-12 active with 11 ingestors) |
| Prometheus series | ~800 time series |

### 15.2 Scaling Boundaries

| Bottleneck | Current Limit | Mitigation |
|------------|--------------|------------|
| Feed concurrency | 5 simultaneous | Increase semaphore size |
| DB pool | 25 connections | Increase MaxConns |
| NVD rate limit | 5 req/30s (no key) | Add API key for 10x |
| EPSS page delay | 100ms fixed | Make configurable |
| Memory | 512 MB (Fly.io) | Increase VM size |
| Single instance | 1 replica | Acceptable for ingestion workload |

### 15.3 Single-Instance Design Rationale

TigerFetch is intentionally single-instance:
- Cursor-based ingestion is not designed for concurrent writers
- Feed sources have rate limits that multiply with replicas
- The workload is I/O-bound (HTTP fetches + DB writes), not CPU-bound
- A single shared-CPU VM with 512 MB handles the full feed inventory comfortably

---

## Appendix A: Migration History

| # | File | Change |
|---|---|---|
| 1 | `20250425_create_tables.sql` | Create archive + current tables |
| 2 | `20250525_add_uuid_and_unique_guid.sql` | Add UUID primary key, unique guid index |
| 3 | `20250526_create_views_for_feed_qa.sql` | 10 QA views + expression indexes |
| 4 | `20250531_create_cve_raw.sql` | Create cve_raw table |
| 5 | `20250532_create_cve_enriched.sql` | Create cve_enriched table + indexes |
| 6 | `20250601_create_ingest_state.sql` | Create ingest_state cursor table |
| 7 | `20250602_fix_ingest_state.sql` | Idempotent re-creation |
| 8 | `20250913_fix_checksums.sql` | No-op (checksum reconciliation) |
| 9 | `20251214_create_epss_daily.sql` | Partitioned EPSS table + movers view |
| 10 | `20260329_fix_archive_current_cardinality.sql` | Composite unique key (guid, feed_url) |
| 11 | `20260412_drop_epss_daily_raw.sql` | Drop redundant `raw` column (~23% size reclaim per partition) |
| 12 | `20260511_create_cve_kev.sql` | KEV as a first-class typed table (replaces `source='CISA-KEV'` anti-pattern) |
| 13 | `20260512_create_cve_enriched_history.sql` | Append-only change-log + trigger |
| 14 | `20260513_archive_notify_trigger.sql` | `pg_notify('article_ingested', guid)` for tiger-eye LISTEN |
| 15 | `20260516120000_comparison_views_legacy_vs_public.sql` | `legacy.*` vs `public.*` audit views (actor normalisation, KEV demotion, analysis comparison) |
| 16 | `20260516130000_create_osv_vulns.sql` | OSV advisories table + per-ecosystem indexes |
| 17 | `20260516140000_create_ghsa_advisories.sql` | GitHub Security Advisory table |
| 18 | `20260516150000_create_urlhaus_urls.sql` | URLhaus URLs table |
| 19 | `20260516160000_create_nuclei_templates.sql` | Nuclei templates table |
| 20 | `20260516170000_create_msf_modules.sql` | Metasploit modules table |
| 21 | `20260516180000_create_threatfox_iocs.sql` | ThreatFox IOCs table |
| 22 | `20260516190000_create_malwarebazaar_samples.sql` | MalwareBazaar samples table |
| 23 | `20260516_materialize_epss_to_cve_enriched.sql` | `materialize_epss_to_cve_enriched()` function + first-run fill |

## Appendix B: Makefile Targets

```
make all        lint + audit + test + build (default)
make build      Build binary with version/commit ldflags
make run        go run ./cmd/tigerfetch
make test       go test -v -race ./...
make coverage   Generate HTML coverage report
make lint       GolangCI-Lint
make fmt        go fmt ./...
make audit      govulncheck on compiled binary
make sec        gosec SAST scan
make trivy      Build + scan Docker image
make tools      Install tooling to ./bin
make help       Show all targets
```
