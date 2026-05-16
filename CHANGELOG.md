# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

#### EPSS materialisation (`20260516_materialize_epss_to_cve_enriched.sql`)
- New `materialize_epss_to_cve_enriched()` PL/pgSQL function that pulls
  the latest EPSS score per CVE from the `epss_daily` partitions and
  writes it to `cve_enriched.epss`. Idempotent (only updates rows whose
  score actually changed); safe to call on a schedule.
- Migration runs the function once on apply, producing the immediate
  data-quality fix.
- **Pre-migration coverage**: 0 / 351,080 rows (0%) had EPSS populated
  in `cve_enriched`, despite ~11M scores being available across the
  partitions. Analyst queries of the form `WHERE epss >= 0.5` returned
  zero rows — the data was unjoinable.
- **Post-migration coverage**: 333,455 / 351,080 rows (95.0%). The 5%
  gap is CVEs with no EPSS score yet (typically very new entries; EPSS
  publishes with a slight lag after NVD).
- Future EPSS pulls should call this function post-fetch (cron,
  pg_cron, or tigerfetch hook — TBD).

#### Comparison views: legacy.* vs public.* (`20260516120000_comparison_views_legacy_vs_public.sql`)
- Three analyst-facing views exposing what the May-2026 migration
  changed structurally. They join the historical `legacy.*` schema
  (restored from the prod fly.io dump) with `public.*` (the live new
  model).
- `v_actor_normalisation_demo` — one-row summary contrasting legacy's
  free-text `analysis.potential_threat_actors` JSON arrays with the new
  `public.threat_actors` canonical entities + `analysis_actor` join
  table. Reports the noise-reduction ratio (distinct lowercased raw
  strings ÷ canonical entities). Current value: **15.2×** (7,412 →
  488).
- `v_kev_demotion` — per-CVE side-by-side of `public.cve_kev` typed
  columns vs the same fields trapped inside `legacy.cve_enriched.json`
  (where `source='CISA-KEV'`). Surfaces concrete losses, e.g. the
  legacy `knownRansomwareCampaignUse` was stored as the string
  `"Unknown"` rather than the typed boolean used now.
- `v_analysis_comparison` — for each of the 1,608 GUIDs enriched by
  *both* the v0.1.x (legacy) and v0.2.x (new) pipelines, joins the two
  verdicts side-by-side: severity agreement, confidence delta,
  threat-type categorisation (new-only), per-row provenance, and
  timestamps. Lets analysts spot-check model drift across the
  migration.

---

## [1.3.1] - 2026-05-13

### Fixed
- **CISA KEV ingest dropped `knownRansomwareCampaignUse` and `cwes[]` fields.** The Go `KevVuln` struct in `internal/cve/kev.go` was missing both, so the round-trip `json.Marshal(KevVuln)` silently dropped them when writing to `cve_enriched.json`. Result: 1,590 KEV entries in production had `known_ransomware_use=false` regardless of upstream value, and their CWE classifications were unrecoverable from local data. Added both fields to the struct (`KnownRansomwareCampaignUse string` and `CWEs []string`) and extended the integration test to assert round-trip persistence via a `SELECT json ->> 'knownRansomwareCampaignUse'` check.
- After redeploying tigerfetch, the next KEV catalog refresh will repopulate both fields. To backfill historical entries earlier than that, re-run `scripts/backfill_cve_kev.sql` once the corrected JSON has landed in `cve_enriched`.

### Known issue (now resolved)
- The "Known issue" noted in v1.3.0 above (KEV ingest gap) is fixed by this release.

---

## [1.3.0] - 2026-05-13

### Added

#### CISA KEV as a first-class table (`20260511_create_cve_kev.sql`)
- New `cve_kev` table promoting CISA Known Exploited Vulnerabilities to its own entity, replacing the `cve_enriched(source='CISA-KEV')` anti-pattern (KEV is an *attribute* of a CVE, not a competing authoritative source)
- Mirrors the upstream CISA catalogue schema: `vendor_project`, `product`, `vulnerability_name`, `short_description`, `required_action`, `date_added`, `due_date`, `known_ransomware_use`, `cwes[]`, plus raw jsonb fallback
- Withdrawn entries flagged via `withdrawn_at` rather than deleted (historical record preserved)
- Partial indexes: `idx_cve_kev_active`, `idx_cve_kev_due_date`, `idx_cve_kev_ransomware`, `idx_cve_kev_vendor_product`
- Backfill script `scripts/backfill_cve_kev.sql` — idempotent, populated 1,590 entries on first run

#### Append-only CVE change log (`20260512_create_cve_enriched_history.sql`)
- New `cve_enriched_history` table — one row per actual state-change on `cve_enriched`
- PL/pgSQL trigger `trg_cve_enriched_history` on INSERT / UPDATE / DELETE fires `cve_enriched_capture_history()`. Skips no-op UPDATEs
- Captures `prev_json` + scalar `prev_cvss_base` / `prev_epss` / `prev_modified`, plus `changed_fields TEXT[]` with synthetic keys (`__cvss_base__`, `__epss__`, `__modified__`) when surfaced scalar columns change
- Lets us answer "why did this CVE's score change?" / "when did NVD add this CPE configuration?" without scraping NVD's changelog

#### `pg_notify` trigger on archive (`20260513_archive_notify_trigger.sql`)
- `AFTER INSERT ON archive` fires `pg_notify('article_ingested', NEW.guid)`
- Enables tiger-eye's sub-second LISTEN-driven enrichment (drops wake-up latency from up-to-60s polling lag to <1s)
- AFTER trigger — rolled-back transactions don't generate notifies (pg_notify queues are flushed on commit only)
- No UPDATE/DELETE handling — re-enrichment policy on edits is handled by tiger-eye's `input_hash` compare on poll

### Companion changes in `tiger-eye`
- Read-only SQLAlchemy models for `cve_kev` and `cve_enriched_history`
- Tiger-eye writer now emits per-row provenance (`model_id`, `prompt_version`, `pipeline_version`, `prompt_tokens`, `response_tokens`, `latency_ms`, `input_hash`)
- Strict OpenAI `json_schema` response_format (PROMPT_VERSION=v3)
- LISTEN/NOTIFY listener subscribes to `article_ingested`
- See `tiger-eye/CHANGELOG.md` v0.2.0 for the full set

### Known issue
- The tigerfetch CISA-KEV ingestor does not currently persist the upstream `knownRansomwareCampaignUse` or `cwes[]` fields into `cve_enriched.json`. After backfill, all 1,590 `cve_kev` rows have `known_ransomware_use=false` even where the upstream feed marks otherwise. Fix is a one-line addition to the JSON projection in the KEV ingest path.

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
