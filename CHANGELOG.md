# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.4.0] - 2026-05-17

This release closes out the **Tier-1 intel-source set** end-to-end. Beyond the
seven new ingestors it lands the abuse.ch trio (URLhaus / ThreatFox /
MalwareBazaar) sharing a single `ABUSECH_API_KEY`, the Grafana dashboard set
(four dashboards), and the `Config.toml.example` gap that was silently leaving
OSV / GHSA / MSF / Nuclei disabled on fresh deploys.

### Added

#### ThreatFox + MalwareBazaar ingest (Tier-1 abuse.ch) — `internal/abusech/`, migrations `20260516180000_create_threatfox_iocs.sql`, `20260516190000_create_malwarebazaar_samples.sql`
- New `ThreatfoxRunner` polls `POST threatfox-api.abuse.ch/api/v1/`
  with `query=get_iocs`, 7-day window, hourly cadence. Persists every
  IOC to a new `threatfox_iocs` table (`ioc_id` PK), denormalising
  `ioc_type` / `threat_type` / `malware{,_alias,_printable,_malpedia}` /
  `confidence_level` / `first_seen` / `last_seen` / `tags[]` (GIN) plus
  full upstream record in `raw` jsonb.
- New `MalwarebazaarRunner` polls `POST mb-api.abuse.ch/api/v1/` with
  `selector=time` (60 min window), hourly cadence. Persists each sample
  to `malwarebazaar_samples` (`sha256_hash` PK) with `signature`,
  `tags[]`, `file_type`, `file_size`, `reporter`, `intelligence` /
  `vendor_intel` jsonb.
- Both runners use the unified `ABUSECH_API_KEY` env var (URLhaus
  switched from key-less to authenticated alongside, mirroring the
  abuse.ch policy change). Both short-circuit cleanly when the key is
  unset, so URLhaus + non-abuse.ch sources continue working in
  key-less environments.
- Prometheus: `tigerfetch_threatfox_fetches_total{status}`,
  `tigerfetch_threatfox_iocs_processed_total`,
  `tigerfetch_threatfox_run_duration_seconds` (and the matching
  malwarebazaar trio).
- Verified locally: ThreatFox 3,488 IOCs across {domain, url, ip:port,
  sha256_hash} kinds; MalwareBazaar 319 samples; URLhaus 25,784 URLs
  with 2,155 currently online. All three tables joinable to
  `analysis_malware.canonical_name` and to tiger-eye's `analysis.key_iocs`.

#### `Config.toml.example` — explicit `enabled = true` blocks for every Tier-1 source
- Pre-this-release: only `[nvd]` / `[kev]` / `[epss]` were materialised in
  the example, so a fresh deploy that copied `Config.toml.example` →
  `Config.toml` would quietly run only those three. OSV / GHSA / MSF /
  Nuclei were merged but config-dark.
- Now: explicit `[osv]` (with the 11-ecosystem default list) / `[ghsa]` /
  `[urlhaus]` / `[threatfox]` / `[malwarebazaar]` / `[nuclei]` / `[msf]`
  blocks. `docker-compose.yml` gains `env_file: .env` on the tigerfetch
  service so the abuse.ch + GHSA tokens propagate into the container.
- Removes the dead `[mitre]` block — no Go code referenced it.

#### Grafana dashboard set — `grafana/dashboards/{threat-intelligence,tiger-eye,tiger-watch}.json` + `tigerfetch-overview.json` row
- **Tier-1 Threat-Intel Sources** row added to `tigerfetch-overview`:
  per-source records-processed stat, success/error run-rate
  timeseries, and p95 run duration across all 7 Tier-1 ingestors.
- **threat-intelligence** dashboard gains an OSV / GHSA / URLhaus /
  ThreatFox / MalwareBazaar / Nuclei / MSF volume row, plus SBOM-package
  coverage panels powered by tiger-watch's lake.
- **tiger-eye** dashboard (new): analysis volume, DLQ depth (retryable +
  exhausted), model cost per day, per-prompt-version cost, p95 LLM
  latency, embedding coverage.
- **tiger-watch** dashboard (new): SBOM matches, advisories per
  service, version-range eval throughput, "would have been a false
  positive without range filter" delta.
- All four datasources auto-provisioned (`prometheus`, `pg`).
- Three Prometheus scrape jobs (`tigerfetch`, `tiger-eye`,
  `tiger-watch`) — adds the previously-missing `tiger-watch` target so
  its dashboard isn't dark.

### Changed
- README.md refreshed to reflect the post-Tier-1 shape (all 11 ingestors,
  4 dashboards, env-var surface, project structure).
- `docs/SOURCES-TIERED.md` — Tier-1 marked complete; Tier-2/3 queue updated.

### Fixed
- ThreatFox timestamps occasionally carry a trailing timezone
  abbreviation (`2024-01-15 12:00:00 UTC`) that `time.Parse(time.RFC3339)`
  refuses. Added a tolerant parser that strips the trailing token.
- `gofmt` — blank comment line before `parseTime` trailer in
  `internal/abusech/threatfox.go`.
- `docker-compose.yml` now pins the database image to
  `pgvector/pgvector:pg16` so the pgvector extension survives a
  `docker compose down -v` + recreate (was previously falling back to
  the postgres:16 base, leaving tiger-eye's embeddings unwritable).

---

## [Pre-1.4.0 / detail] — items rolled into v1.4.0 above

This section retains the per-ingestor detail that lived in the
`[Unreleased]` block before the v1.4.0 cut.

#### Metasploit module metadata ingest (Tier-1) — `internal/msf/`, migration `20260516170000_create_msf_modules.sql`
- New `MsfRunner` fetches Rapid7's pre-extracted JSON cache at
  `raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json`
  — a single ~10 MB file with every module's metadata already
  structured. Avoids any Ruby parsing.
- New `msf_modules` table: `fullname` PK (e.g. `exploit/linux/http/foo`),
  `module_type`, `rank` + `rank_label` (manual / low / average / normal
  / good / great / excellent), `disclosure_date`, `authors[]`,
  `refs[]`, `cves[]` (denormalised from refs), `platforms[]`,
  `aliases[]`, plus full upstream record in `raw` jsonb.
- 6 indexes including GIN on `cves`/`platforms`, partial btree on
  `disclosure_date DESC WHERE NOT NULL`, btree on `rank DESC`.
- Idempotent upsert keyed on `raw IS DISTINCT FROM EXCLUDED.raw` so
  unchanged modules are no-ops on re-run.
- Prometheus: `tigerfetch_msf_fetches_total{status}`,
  `tigerfetch_msf_modules_processed_total`,
  `tigerfetch_msf_run_duration_seconds`.
- Verified locally: 6,632 modules loaded in 4 s; 3,141 distinct CVEs
  covered; module mix 2,648 exploit / 2,141 payload / 1,336 auxiliary /
  432 post / 49 encoder / 14 nop / 12 evasion; **1,368 excellent-rank +
  296 great-rank** weaponised exploits.
- 7 unit tests covering CVE extraction (case-insensitive + dedup +
  filtering OSVDB/URL/EDB refs), platform splitting, date parsing,
  NUL-stripping, rank-label mapping.
#### Nuclei templates ingest (Tier-1 source) — `internal/nuclei/`, migration `20260516160000_create_nuclei_templates.sql`
- New `NucleiRunner` downloads the main-branch tarball of
  `github.com/projectdiscovery/nuclei-templates`, stream-walks the tar
  entries in-memory, parses every YAML under the configured subdirs
  (default: `http/cves/`, `http/vulnerabilities/`, `dns/`,
  `network/cves/`, `file/`, `javascript/cves/`, `ssl/`) and upserts
  every template into the new `nuclei_templates` table.
- Idempotent: SHA-256 of the YAML body is the change-detection key;
  re-runs touch zero rows when there are no upstream changes.
- CVE extraction collects refs from three sources (classification
  `cve-id`, `tags` field, template `id`) and dedupes uppercase.
- Handles the Nuclei YAML quirks where `author`, `tags`, `cve-id`,
  `cwe-id` can be either a single scalar or a sequence.
- NUL-byte stripping on text columns (some templates carry literal
  `0x00` in payload examples; Postgres text rejects them).
- Prometheus: `tigerfetch_nuclei_fetches_total{status}`,
  `tigerfetch_nuclei_templates_processed_total`,
  `tigerfetch_nuclei_run_duration_seconds`.
- Verified locally: 5,558 templates loaded in 4 s; 4,103 distinct CVEs
  covered; severity distribution 1,610 critical + 1,581 high + 1,808
  medium + 481 info + 62 low + 16 unknown.
- 9 unit tests covering tar-entry path normalisation, subdir
  filtering, YAML scalar/sequence flexibility, CVE/CWE extraction,
  template parsing.

#### URLhaus ingest (Tier-1 abuse.ch) — `internal/abusech/`, migration `20260516150000_create_urlhaus_urls.sql`
- New `UrlhausRunner` polls the public abuse.ch URLhaus CSV feed
  (`urlhaus.abuse.ch/downloads/csv_recent/` — no auth) and upserts
  every row into a new `urlhaus_urls` table. The `id` column is the
  URLhaus internal numeric id, allowing idempotent re-runs that only
  touch rows whose `url_status` or `last_online` actually changed.
- New `urlhaus_urls` columns: `url` (indexed), `url_status`, `threat`,
  `tags[]` (GIN), `date_added`, `last_online`, `reporter`, `urlhaus_link`,
  plus full CSV row in `raw` text for round-trip preservation.
- Five indexes including GIN on `tags` for malware-family lookups and
  partial btree on `last_online DESC WHERE url_status = online` for
  the live-IOC analyst view.
- Prometheus: `tigerfetch_urlhaus_fetches_total{status}`,
  `tigerfetch_urlhaus_rows_processed_total`,
  `tigerfetch_urlhaus_run_duration_seconds`.
- Verified locally: 24,908 URLs loaded in a single fetch; 2,106
  currently online; 47 distinct reporters; tags include Mozi /
  ClearFake / mirai / SnappyClient — directly joinable to
  `analysis_malware.canonical_name`.
- Package layout (`internal/abusech/`) is structured so ThreatFox and
  MalwareBazaar can land alongside URLhaus once an abuse.ch API key
  is configured (both moved to auth-required in 2024).

#### GHSA ingest (Tier-1 source) — `internal/ghsa/`, migration `20260516140000_create_ghsa_advisories.sql`
- New `GhsaRunner` polls the GitHub Security Advisory Database REST API
  (`api.github.com/advisories`) with incremental `?modified=>{cursor}`
  filtering and follows the `Link: rel="next"` pagination. Cursor
  persisted in `ingest_state` (source=`GHSA`); progress survives
  errors mid-stream so a rate-limit failure doesn't replay the run.
- New `ghsa_advisories` table denormalises hot columns: `ghsa_id` (PK),
  `cve_id`, `severity` (text enum), `cvss_v3` + `cvss_v3_vector`,
  `cvss_v4` + `cvss_v4_vector`, `cwes[]`, `ecosystems[]`,
  `package_names[]`, `published` / `updated` / `withdrawn` —
  alongside `vulnerabilities` + `refs` jsonb and a `raw` jsonb that
  preserves the full upstream record.
- Eight indexes including GIN on `package_names` (joins to
  tiger-watch SBOM matching), GIN on `cwes`, btree on `cve_id` (links
  to NVD / OSV via alias), partial btree on active (non-withdrawn)
  advisories.
- Prometheus: `tigerfetch_ghsa_fetches_total{status}`,
  `tigerfetch_ghsa_advisories_processed_total`,
  `tigerfetch_ghsa_pages_fetched_total`,
  `tigerfetch_ghsa_run_duration_seconds`,
  `tigerfetch_ghsa_rate_limit_remaining`.
- Anonymous works (60 req/h); a GitHub PAT in `cfg.GHSA.Token` lifts
  the cap to 5,000 req/h — needed for the initial ~30K-advisory
  backfill, optional for incremental runs.
- Verified locally: 271 advisories loaded before hitting the
  anonymous rate limit; all 271 had structured CVSS, 187 had CWEs
  across 8 ecosystems. Cursor advance + idempotent upsert
  (`WHERE updated IS DISTINCT FROM EXCLUDED.updated`) verified.
- 8 unit tests covering `Link` header parsing, identifier extraction,
  CWE/ecosystem/package-name dedup, time parsing.

#### OSV ingest (Tier-1 source) — `internal/osv/`, migration `20260516130000_create_osv_vulns.sql`
- New `OsvRunner` polls per-ecosystem OSV bundles
  (`osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip`) and upserts
  every advisory into a new `osv_vulns` table. Configurable ecosystems
  list (PyPI / npm / Go / Maven / RubyGems / crates.io / Packagist /
  NuGet / Pub / Hex / Hackage / …). Idempotent: re-fetching with no
  upstream changes touches zero rows thanks to a `WHERE modified IS
  DISTINCT FROM EXCLUDED.modified` guard.
- `osv_vulns` columns: typed denormalisations for `id`, `ecosystem`,
  `package_names[]`, `aliases[]` (CVE IDs etc.), `cvss_v3`, `published`,
  `modified`, `withdrawn`; plus `affected`/`refs`/`severity` jsonb and a
  `raw` jsonb that preserves the full upstream advisory.
- Indexes: GIN on `package_names` (joins to tiger-watch SBOM matching),
  GIN on `aliases` (CVE-ID lookups), btree on `modified DESC`, partial
  btree on active (non-withdrawn) advisories per ecosystem, partial
  btree on `cvss_v3` where present.
- Prometheus: `tigerfetch_osv_fetches_total{ecosystem,status}`,
  `tigerfetch_osv_vulns_processed_total{ecosystem}`,
  `tigerfetch_osv_run_duration_seconds`.
- Verified locally: 19,563 PyPI advisories loaded in 13 s on first run;
  re-run touches 0 rows (idempotent).
- Known limitation: `cvss_v3` is NULL for advisories that publish only
  the CVSS vector (the majority of GHSA-sourced PyPI entries — 4,971 of
  19,563). Adding a CVSS-vector evaluator is a follow-up.

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
