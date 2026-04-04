# TigerFetch System Design Document

> **Version:** 1.1.1 | **Date:** 2026-03-29 | **Status:** Production
> **Service:** `tigerfetch` | **Language:** Go 1.26.1 | **Database:** PostgreSQL 16

---

## 1. Overview

TigerFetch is a single-binary cybersecurity OSINT ingestion service that continuously collects threat intelligence from 22 RSS/Atom feeds and 3 structured vulnerability APIs (NVD, CISA KEV, FIRST EPSS), normalises the data, and stores it in PostgreSQL for downstream consumption.

It is designed as an **operational control plane** — not a user-facing API — optimised for reliability, idempotency, and observability at modest scale.

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Single binary, zero runtime deps** | One Go binary with embedded migrations |
| **Idempotent ingestion** | `ON CONFLICT` clauses + cursor tracking prevent duplicates |
| **Fail-safe isolation** | Each data source runs in its own goroutine; one failure cannot cascade |
| **Observable by default** | 40+ Prometheus metrics, structured logging, health endpoint |
| **Secure by construction** | HTML sanitisation, parameterised SQL, non-root container |

---

## 2. Architecture

### 2.1 System Context (C1)

```
                           +-----------------+
                           |   TigerFetch    |
                           |   (tigerfetch)  |
                           +--------+--------+
                                    |
             +----------+-----------+-----------+----------+
             |          |           |           |          |
        +----v---+ +----v----+ +---v----+ +----v----+ +---v--------+
        | 22 RSS | | NVD API | | KEV    | | EPSS   | | PostgreSQL |
        | Feeds  | | (NIST)  | | (CISA) | | (FIRST)| |    16      |
        +--------+ +---------+ +--------+ +--------+ +---+--------+
                                                          |
                                                    +-----v------+
                                                    | Prometheus  |
                                                    | (scrapes    |
                                                    |  :9101)     |
                                                    +-------------+
```

### 2.2 Container View (C2)

```
+--tigerfetch binary (single process)--------------------------------------+
|                                                                          |
|  main.go (composition root)                                              |
|  +-----------+  +----------+  +----------+  +----------+  +-----------+ |
|  | HTTP      |  | Feed     |  | NVD      |  | KEV      |  | EPSS      | |
|  | Server    |  | Ingestor |  | Runner   |  | Runner   |  | Runner    | |
|  | :9101     |  | (5 slots)|  | (1h poll)|  | (24h)    |  | (24h)     | |
|  +-----------+  +----------+  +----------+  +----------+  +-----------+ |
|        |              |             |             |              |        |
|  +-----v--------------v-------------v-------------v--------------v-----+ |
|  |                    pgxpool (max 25 conns)                           | |
|  +---------------------------------------------------------------------+ |
+--------------------------------------------------------------------------+
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
  cve/kev.go                 CISA KEV: single-file catalog sync
  cve/epss.go                FIRST EPSS: paginated CSV, COPY FROM bulk load
  metrics/metrics.go         40+ Prometheus metric definitions (promauto)
  metrics/middleware.go      HTTP request/duration instrumentation
  metrics/dbcollector.go     Live pgxpool.Stat() collector

migrations/
  10 SQL files               Goose-managed, embedded at build time
```

---

## 3. Data Model

### 3.1 Entity Relationship Diagram

```
+------------------+       +------------------+
|     archive      |       |     current      |
|------------------|       |------------------|
| id (UUID) PK     |       | id (UUID) PK     |
| guid             |       | guid             |    UNIQUE(guid, feed_url)
| feed_url         |       | feed_url         |    on both tables
| title            |       | title            |
| link             |       | link             |
| published        |       | published        |
| content          |       | content          |    archive: INSERT only
| summary          |       | summary          |    current: UPSERT
| author           |       | author           |
| categories[]     |       | categories[]     |
| entry_updated    |       | entry_updated    |
| feed_title       |       | feed_title       |
| feed_description |       | feed_description |
| feed_language    |       | feed_language    |
| inserted_at      |       | inserted_at      |
+------------------+       +------------------+


+------------------+       +---------------------------+
|   cve_enriched   |       |       epss_daily          |
|------------------|       |---------------------------|
| cve_id      PK   |       | as_of (DATE)   PK         |
| source      PK   |       | cve_id         PK         |
| json (JSONB)     |       | epss (NUMERIC)            |
| cvss_base        |       | percentile (NUMERIC)      |
| epss             |       | raw (JSONB)               |
| modified         |       | inserted_at               |
+------------------+       +---------------------------+
  Sources:                  PARTITION BY RANGE (as_of)
  - 'NVD'                   Monthly: epss_daily_y2026m03
  - 'CISA-KEV'

+------------------+
|   ingest_state   |
|------------------|
| source (TEXT) PK |       Cursor tracking:
| cursor (TEXT)    |       - NVD: RFC3339 timestamp
+------------------+       - KEV: catalog version/date
```

### 3.2 Table Semantics

| Table | Write Pattern | Dedup Strategy | Growth Rate |
|-------|--------------|----------------|-------------|
| `archive` | Append-only | `ON CONFLICT (guid, feed_url) DO NOTHING` | ~700 items/cycle |
| `current` | Last-write-wins | `ON CONFLICT (guid, feed_url) DO UPDATE` | Bounded by unique items |
| `cve_enriched` | Upsert | `ON CONFLICT (cve_id, source) DO UPDATE` | ~270k NVD + 1.2k KEV |
| `epss_daily` | Daily bulk load | Check date exists, skip if present | ~300k rows/day |
| `ingest_state` | Upsert | `ON CONFLICT (source) DO UPDATE` | 2-3 rows total |

### 3.3 Indexes

| Table | Index | Purpose |
|-------|-------|---------|
| archive | `archive_guid_feed_key (guid, feed_url)` UNIQUE | Deduplication |
| current | `current_guid_feed_key (guid, feed_url)` UNIQUE | Deduplication |
| current | `idx_current_feed_url (feed_url)` | Feed filtering |
| current | `idx_current_published (published)` | Time-range queries |
| current | `idx_current_content_null` (expression) | Feed QA views |
| current | `idx_current_summary_null` (expression) | Feed QA views |
| cve_enriched | `idx_cve_enriched_cvss (cvss_base)` | Severity sorting |
| cve_enriched | `idx_cve_enriched_epss (epss)` | Risk filtering |
| cve_enriched | `idx_cve_enriched_mod (modified DESC)` | Delta polling |
| epss_daily | `idx_epss_daily_cve_id (cve_id)` | CVE lookups |
| epss_daily | `idx_epss_daily_as_of_epss (as_of, epss DESC)` | Ranked risk queries |

### 3.4 Views (Feed Quality Analytics)

11 views provide operational visibility into feed content quality:

| View | Purpose |
|------|---------|
| `v_feed_coverage_summary` | Per-feed completeness stats (total, missing content/summary, %) |
| `v_missing_both_per_feed` | Feeds ranked by missing content+summary count |
| `v_missing_both_by_day` | Missing content trends over time |
| `v_percent_missing_both` | Percentage-based feed health |
| `v_epss_movers_24h` | CVEs with largest EPSS score changes in 24 hours |

---

## 4. Data Sources & Ingestion Pipelines

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
ingest_interval = "1h"             # Feed polling frequency
server_bind     = "0.0.0.0:9101"   # HTTP server bind address

[nvd]
enabled         = true
poll_interval   = "1h"
page_size       = 2000             # Results per API page
api_key         = ""               # Optional; enables 50 req/30s (vs 5)

[kev]
enabled         = true
poll_interval   = "24h"
url             = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

[epss]
enabled         = true
poll_interval   = "24h"
url             = "https://api.first.org/data/v1/epss"
page_size       = 5000

[[feeds]]
name            = "CISA Cybersecurity Alerts"
url             = "https://us-cert.cisa.gov/ncas/alerts.xml"
feed_type       = "official"
tags            = ["government", "alerts"]
```

### 6.3 Environment Variables

| Variable | Maps To | Required |
|----------|---------|----------|
| `DATABASE_URL` | `database_url` | Yes |
| `LOG_LEVEL` | slog level (DEBUG/INFO/WARN/ERROR) | No (default: INFO) |
| `NVD_API_KEY` | `nvd.api_key` | No |
| `SERVER_BIND` | `server_bind` | No |
| `INGEST_INTERVAL` | `ingest_interval` | No |

---

## 7. Observability

### 7.1 Metrics (Prometheus)

**38 metrics exposed at `GET /metrics` with prefix `tigerfetch_`.**

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

Two provisioned dashboards are auto-loaded via `grafana/dashboards/` and require zero manual setup.

#### TigerFetch Operations (`tigerfetch-ops`)

Operational dashboard sourced from Prometheus. 7 rows, ~30 panels:

| Row | Panels | Purpose |
|-----|--------|---------|
| System Overview | Uptime, Go version, goroutines, memory, GC pause | Process health at a glance |
| Feed Ingestion | Success rate, items/min, empty content ratio, freshness, per-feed breakdown | Feed pipeline health |
| NVD Enrichment | Fetch rate, CVEs processed, cursor lag, batch size, run duration | NVD catch-up progress |
| EPSS & KEV | EPSS records, run outcomes, KEV vuln count, cursor lag | Enrichment pipeline status |
| Upstream HTTP | Latency heatmap, P50/P99 by source, error rate | External API performance |
| DB Pool | Utilisation gauge, connection breakdown, acquire latency, exhaustion events | Database pressure |
| Runtime | Goroutine count, heap usage, GC frequency | Go runtime internals |

Template variables: `$feed` (feed name filter), `$source` (upstream source filter).

#### Threat Intelligence (`tigerfetch-intel`)

Analytical dashboard sourced from PostgreSQL. 5 rows, ~20 panels:

| Row | Panels | Purpose |
|-----|--------|---------|
| Threat Landscape Overview | Total CVEs, KEV entries, critical CVEs, EPSS records, high-risk count, feed items (7d) | Key numbers at a glance |
| EPSS — Exploit Prediction | Top 25 most exploitable CVEs, biggest 24h movers, score distribution, daily record trend | Exploitation probability analysis |
| Danger Zone — CVSS x EPSS | Combined table: CVEs with high severity AND high exploit probability, risk score, KEV flag | Priority-1 patching candidates |
| NVD — Vulnerability Landscape | CVSS distribution, CVEs by severity over time, latest critical CVEs, CISA KEV catalog | Vulnerability landscape overview |
| Feed Intelligence | Feed volume timeline, content coverage by feed, latest 50 feed items with links | RSS/Atom feed health and content |

Template variables: `$epss_threshold`, `$cvss_threshold`, `$feed_source`.

Risk score formula: `ROUND((cvss_base * epss * 10) / 10, 2)` — produces a 0–10 scale combining severity with exploitation likelihood.

#### Datasource Configuration

Both datasources are provisioned via `grafana/provisioning/datasources/datasource.yml`:

| Datasource | Type | UID | Target | Default |
|------------|------|-----|--------|---------|
| Prometheus | `prometheus` | `prometheus` | `http://prometheus:9090` | Yes |
| PostgreSQL | `postgres` | `pg` | `db:5432` | No |

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

### 13.1 Direct Dependencies (7)

| Package | Version | Purpose |
|---------|---------|---------|
| `jackc/pgx/v5` | 5.8.0 | PostgreSQL driver with connection pooling |
| `microcosm-cc/bluemonday` | 1.0.27 | HTML sanitisation (XSS prevention) |
| `mmcdole/gofeed` | 1.3.0 | RSS/Atom feed parsing |
| `pressly/goose/v3` | 3.26.0 | Database migration management |
| `prometheus/client_golang` | 1.23.2 | Prometheus metrics instrumentation |
| `spf13/viper` | 1.21.0 | Configuration management (TOML + env) |
| `stretchr/testify` | 1.11.1 | Test assertions and requirements |

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
|-----------|-------|
| RSS/Atom feeds | 22 sources, ~700 items per cycle |
| NVD CVEs | ~270,000 total (120-day sliding window) |
| KEV vulnerabilities | ~1,200 total (single catalog) |
| EPSS records | ~300,000 per daily snapshot |
| DB connections | Max 25 (typical: 4-6 active) |
| Prometheus series | ~500 time series |

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
|---|------|--------|
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
