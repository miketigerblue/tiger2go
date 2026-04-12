# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-04-12

### Added
- **Sleeper CVE Alerting** — detects CVEs that jump from <10% to ≥50% EPSS over a configurable lookback window and sends notifications via webhooks
- **Slack Block Kit notifications** — rich formatted alerts with NVD links, coloured CVSS badges, CWE tags, and truncated descriptions (capped at 10 CVEs per message)
- **Generic webhook support** — flat JSON payload for non-Slack integrations
- **Cursor-based alert deduplication** — prevents duplicate notifications using `ingest_state` tracking
- **4 Prometheus alerting metrics** — `alerting_runs_total`, `sleeper_cves_detected_total`, `webhooks_sent_total`, `alerting_run_duration_seconds`
- **EPSS Score Distribution panel** — bargauge with semantic risk colours (green → red) on the Threat Intelligence dashboard
- **EPSS Coverage & Ingest Health panels** — stat, gauge, and daily log replacing the broken trend timeseries
- **Prometheus persistent volume** — scrape data survives container rebuilds (90-day retention, 1GB cap)

### Changed
- `Config.toml.example` updated with `[alerting]` section and webhook examples
- Removed dead `[mitre]` config section (no Go code references it)

### Fixed
- Grafana 11.6 dashboard panels showing "No data" — added explicit datasource references to all 33 panels in tigerfetch-overview
- EPSS panels on Threat Intelligence dashboard never rendered — replaced `barchart`/`timeseries` with working panel types
- EPSS distribution colours were inverted (high EPSS was green instead of red)

### Removed
- `raw` JSONB column from `epss_daily` — redundant (duplicated cve_id, as_of, epss, percentile); reclaimed ~23% table size per partition

---

## [1.1.1] - 2026-03-29

### Added
- **Grafana Operations Dashboard** (`tigerfetch-ops`) — ~30 Prometheus-powered panels across 7 rows: system overview, feed ingestion health, NVD/EPSS/KEV pipeline status, upstream HTTP latency, DB pool utilisation, Go runtime internals
- **Grafana Threat Intelligence Dashboard** (`tigerfetch-intel`) — ~20 SQL-powered panels across 5 rows: EPSS top 25, 24h movers, CVSS x EPSS danger zone with risk scoring, NVD severity landscape, CISA KEV catalog, feed content coverage
- **PostgreSQL Grafana datasource** — provisioned alongside Prometheus for SQL-powered analytics directly against the data lake
- **Dashboard auto-provisioning** — dashboards and datasources load automatically via `grafana/provisioning/`, zero manual setup
- **Mission statement** in README
- **CHANGELOG.md** — this file

### Changed
- Docker Compose stack now includes Grafana (`:3000`) with provisioned dashboards and dual datasources
- System design document updated with Grafana dashboard documentation (section 7.6) and updated stack diagram (section 9.4)
- README updated with full stack instructions, Grafana dashboard descriptions, and Go 1.26 version requirement
- Datasource references use explicit UIDs (`prometheus`, `pg`) for reliable resolution in provisioned mode

### Fixed
- Grafana provisioned dashboards failing to resolve `{ "type": "postgres" }` datasource (fell back to default Prometheus, causing SQL parse errors)

---

## [1.1.0] - 2026-03-29

### Added
- 40+ Prometheus metrics at `/metrics` — feed health, CVE cursor lag, upstream latency, DB pool stats, HTTP instrumentation, build info
- `/healthz` endpoint for liveness probes
- Structured logging via `log/slog`, configurable with `LOG_LEVEL` env var
- Bounded concurrent feed fetching — semaphore (max 5) with `sync.WaitGroup`
- Context-aware graceful shutdown — all worker loops exit cleanly on SIGTERM
- Integration tests for ingestor (idempotency, empty content, XSS sanitisation, HTTP errors)
- System design document (`docs/SYSTEM_DESIGN.md`)

### Changed
- Go toolchain upgraded from 1.24 to 1.26.1
- CI: golangci-lint-action upgraded from v3 to v7 for Go 1.26 compatibility
- CI: test packages run sequentially (`-p 1`) to prevent migration race conditions
- Archive/current tables use composite unique key `(guid, feed_url)` instead of `(guid)`

### Fixed
- Feed ingestor was never wired into `main.go` — now runs on startup
- Config.toml mounted into Docker container (was relying on broken env var overrides)
- Mixed `log.Printf`/`slog` output — now fully structured via `slog`
- `gofmt` alignment in `dbcollector.go`
- Test migration race condition with `TestMain` pattern

### Security
- Go 1.26.1 resolves CVE-2026-25679 (HIGH — `net/url` IPv6 parsing)
- Trivy container scan passes with 0 HIGH/CRITICAL CVEs
- All 4 CI gates green: lint, SAST (gosec), SCA (govulncheck), container scan (Trivy)

---

## [1.0.0] - 2026-02-09

### Added
- Initial Go port of TigerFetch (Rust → Go)
- RSS/Atom feed ingestion with `gofeed` and `bluemonday` sanitisation
- NVD API v2.0 windowed fetching with rate limiting
- CISA KEV catalog sync
- EPSS daily bulk ingestion (~300k records/day)
- PostgreSQL storage with `pgx/v5` connection pooling
- Embedded schema migrations via `pressly/goose`
- Docker multi-stage build
- GitHub Actions CI pipeline
