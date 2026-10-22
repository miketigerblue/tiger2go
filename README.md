<p align="center">
  <img src="tigerfetch_hunt_the_signal.png" alt="TigerFetch: hunt the signal" width="400" />
</p>

<h1 align="center">TigerFetch</h1>

<p align="center"><strong>Threat-intelligence ingestion for the TigerBlue platform.</strong><br /><em>hunt_the_signal()</em></p>

TigerFetch is a threat-intelligence ingestion engine written in Go. It collects security feeds, vulnerability records, software advisories and exploit signals into a structured PostgreSQL data store, giving security teams a common foundation for investigation and vulnerability prioritisation.

It handles the operational work behind that intelligence: concurrent collection, source-specific rate limits, retries, sanitisation, deduplication, schema migrations and monitoring. The result is a queryable record of external threats that analysts and downstream services can relate to the software they actually run.

## What it delivers

- **Broad source coverage:** RSS/Atom, NVD, CISA KEV, FIRST EPSS, OSV, GitHub Security Advisories, Nuclei, Metasploit and abuse.ch feeds.
- **A shared intelligence store:** normalised records in PostgreSQL, with vulnerability scores, known-exploitation signals, software package ranges and indicators available for downstream analysis.
- **Operational visibility:** Prometheus metrics, health checks and provisioned Grafana dashboards for ingestion health, data coverage and threat intelligence.
- **Actionable changes:** configurable alerts for sharp increases in EPSS exploitation-probability scores, delivered through Slack or generic webhooks.
- **Straightforward deployment:** one Go binary with embedded database migrations, plus Docker Compose for the local stack.

## Where it fits

TigerFetch provides the collection layer of TigerBlue. Intelligence flows from external sources through ingestion and normalisation into PostgreSQL, where analysts and companion services can query it.

| Name | Role |
|---|---|
| **TigerBlue** | The overall security-intelligence platform. |
| **TigerFetch** | Collects, normalises and stores threat intelligence. This repository contains the Go ingestion service. |
| **TigerEye** | Enriches and interprets intelligence, with retrieval for investigation. |
| **TigerWatch** | Matches threat intelligence to products, versions and software bills of materials. |

See the [system design](docs/SYSTEM_DESIGN.md) for the architecture, data model and ingestion semantics. The [engineering rationale](docs/ENGINEERING_RATIONALE.md) explains the Rust-to-Go migration.

**Naming compatibility:** TigerFetch is the product name. The repository slug and Go module remain `tiger2go`; existing import paths, database names and deployment identifiers retain their current values. Use the names shown in the configuration and commands below when building or deploying.

## 🚀 Features

### Ingestors

*   **RSS/Atom feeds**: Parallel fetching of 22 security feeds using `gofeed` with `bluemonday` sanitisation.
*   **CVE enrichment**:
    *   **NVD** — windowed fetching of CVE details (120-day chunks) with API-key rate-limit support (v2.0 API).
    *   **CISA KEV** — first-class typed table (`cve_kev`) with `known_ransomware_use`, `cwes[]`, `vendor_project`, `due_date`. Withdrawn entries flagged, not deleted.
    *   **EPSS** — bulk ingestion of daily Exploit Prediction Scoring System scores (~300k records/day) into a partitioned table; materialised back to `cve_enriched.epss` for analyst queries.
*   **Supply-chain advisories** (Tier-1):
    *   **OSV** — per-ecosystem feeds (`osv-vulnerabilities.storage.googleapis.com`), 11 ecosystems by default.
    *   **GHSA** — GitHub Security Advisory Database, incremental cursor with `Link: rel="next"` pagination, CVSS v3/v4 + per-package vulnerability ranges.
*   **Exploit/IOC signals** (Tier-1):
    *   **CISA KEV** (see above) — authoritative exploited-in-the-wild list.
    *   **Nuclei templates** (`projectdiscovery/nuclei-templates`) — when a CVE has a scanner template, exploit-commodity threshold is crossed.
    *   **Metasploit modules** — Rapid7's `modules_metadata_base.json` cache; `rank_label` (excellent/great/good/normal/…) tells you weaponisation quality.
    *   **abuse.ch URLhaus** — live malicious-URL feed (no auth).
    *   **abuse.ch ThreatFox** — IOC feed (Auth-Key).
    *   **abuse.ch MalwareBazaar** — sample feed (Auth-Key, shared with ThreatFox/URLhaus).
*   **Sleeper CVE alerting** — detects CVEs that jump from < 10 % to ≥ 50 % EPSS over a configurable window; emits Slack Block Kit or generic JSON webhooks.

### Storage and observability

*   **Database**: PostgreSQL storage via `pgx/v5` connection pooling.
*   **Migrations**: Embedded schema migrations via `pressly/goose`.
*   **Observability**: Prometheus metrics (`/metrics`), health checks (`/healthz`), and four provisioned Grafana dashboards.
*   **Grafana dashboards** (all auto-provisioned from `grafana/dashboards/`):
    *   **TigerFetch Operations** — Prometheus-powered: feed health, all 11 ingestor pipelines, upstream HTTP latency, DB pool, Go runtime, sleeper-CVE alerting outcomes. Includes a "Tier-1 Threat-Intel Sources" row.
    *   **Threat Intelligence** — SQL-powered: EPSS top 25, CVSS × EPSS danger zone, NVD severity landscape, CISA KEV catalogue, OSV/GHSA/abuse.ch volume, feed content coverage.
    *   **TigerEye** (`tiger-eye`) — companion dashboard for the Python enrichment pipeline (analysis volume, DLQ depth, model cost, latency).
    *   **TigerWatch** (`tiger-watch`) — companion dashboard for the SBOM matching service (matches, advisories, version-range eval).

## 🛠️ Build & Run

### Prerequisites
*   Go 1.26+
*   PostgreSQL 16+

### Building

```bash
# Build the binary (injects version/commit via ldflags)
make build
```

### Running

Ensure you have a `Config.toml` in the working directory (or use environment variables).

```bash
# Run the application
./tigerfetch
```

The application will:
1.  Run pending database migrations.
2.  Start the HTTP metrics server on `:9101`.
3.  Launch concurrent workers for RSS feeds, NVD, KEV, and EPSS.

### Full Stack (Docker Compose)

```bash
docker compose up --build
```

This starts PostgreSQL, TigerFetch, Prometheus, and Grafana. Dashboards are auto-provisioned:

| Service | URL | Credentials |
|---------|-----|-------------|
| TigerFetch metrics | http://localhost:9101/metrics | — |
| Prometheus | http://localhost:9090 | — |
| Grafana | http://localhost:3000 | admin / admin |

### Testing

Integration tests require a running database connection.

```bash
# Run unit and integration tests
go test -v ./internal/...
```

## ⚙️ Configuration

Configuration is handled via `Config.toml` and environment variables. Each ingestor lives under its own `[section]` and is independently enable-able. See `Config.toml.example` for the canonical, copy-pasteable form (it carries the explicit `enabled = true` blocks needed so a fresh deploy doesn't quietly run only NVD / EPSS / KEV).

| Section | Key | Description |
| :--- | :--- | :--- |
| Global | `database_url` | Postgres DSN connection string |
| Global | `server_bind` | Host:Port for metrics server (default `0.0.0.0:9101`) |
| Global | `ingest_interval` | Feed polling interval (default `1h`) |
| `[[feeds]]` | `name`, `url`, `feed_type`, `tags` | RSS/Atom feed sources |
| `[nvd]` | `enabled`, `api_key`, `poll_interval`, `page_size`, `modified_since` | NVD CVE enrichment, publications and modifications; API key enables 10× rate limit |
| `[kev]` | `enabled`, `poll_interval`, `url` | CISA KEV catalogue |
| `[epss]` | `enabled`, `poll_interval`, `archive_url`, `backfill_days` | FIRST EPSS daily scores, whole days from the archive with self-healing backfill |
| `[osv]` | `enabled`, `poll_interval`, `ecosystems` | OSV per-ecosystem feeds (PyPI, npm, Go, …) |
| `[ghsa]` | `enabled`, `poll_interval`, `token` | GitHub Security Advisory Database (token raises 60 → 5,000 req/h) |
| `[urlhaus]` | `enabled`, `poll_interval` | abuse.ch URLhaus (no auth) |
| `[threatfox]` | `enabled`, `poll_interval` | abuse.ch ThreatFox (Auth-Key) |
| `[malwarebazaar]` | `enabled`, `poll_interval` | abuse.ch MalwareBazaar (Auth-Key) |
| `[nuclei]` | `enabled`, `poll_interval`, `template_subdirs` | ProjectDiscovery Nuclei templates |
| `[msf]` | `enabled`, `poll_interval` | Metasploit Framework module metadata |
| `[alerting]` | `enabled`, `[[alerting.webhooks]]` | Sleeper-CVE detection + Slack / generic webhooks |
| `[maintenance]` | `enabled`, `poll_interval`, `epss_retention_days` | Retention: drops `epss_daily` monthly partitions older than the window (off by default) |

### Environment variables

The `tigerfetch` service reads `env_file: .env` (see `docker-compose.yml`); these override the equivalent `Config.toml` keys:

| Variable | Maps to | Purpose |
|---|---|---|
| `DATABASE_URL` | `database_url` | Postgres DSN |
| `NVD_API_KEY` | `nvd.api_key` | Higher NVD rate limit |
| `GHSA_TOKEN` | `ghsa.token` | GitHub PAT for the 5K req/h tier |
| `ABUSECH_API_KEY` | `urlhaus.auth_key`, `threatfox.auth_key`, `malwarebazaar.auth_key` | Single key shared across the three abuse.ch ingestors |
| `LOG_LEVEL` | slog level | `DEBUG` / `INFO` / `WARN` / `ERROR` (default `INFO`) |

## 🏗️ Project Structure

*   `cmd/tigerfetch`: Application entry point and composition root.
*   `internal/config`: Viper configuration loading (TOML + env).
*   `internal/db`: pgxpool, Goose migrations.
*   `internal/ingestor`: RSS/Atom feed processing.
*   `internal/cve`: NVD, CISA KEV, FIRST EPSS pipelines.
*   `internal/osv`: OSV (Open Source Vulnerabilities) per-ecosystem ingest.
*   `internal/ghsa`: GitHub Security Advisory Database ingest.
*   `internal/abusech`: URLhaus, ThreatFox, MalwareBazaar (shared abuse.ch API-key surface).
*   `internal/nuclei`: ProjectDiscovery Nuclei templates ingest (tarball stream-walker).
*   `internal/msf`: Metasploit module metadata ingest.
*   `internal/alerting`: Sleeper-CVE detection + Slack Block Kit / generic JSON webhook senders.
*   `internal/metrics`: Prometheus metric definitions, pgxpool collector, HTTP middleware.
*   `grafana/`: Provisioned dashboards (`tigerfetch-overview`, `threat-intelligence`, `tiger-eye`, `tiger-watch`) and datasource configuration.
*   `migrations/`: SQL migration files (Goose compatible).
*   `docs/`: Design notes, decision records, and analyst guides.
*   `postgrest/`: PostgREST service over the `api` schema (deployment now lives in [`tigerblue-deployment`](https://github.com/miketigerblue/tigerblue-deployment); see `postgrest/README.md` for the pointer).

## 📚 Documentation

*   [`docs/ENGINEERING_RATIONALE.md`](docs/ENGINEERING_RATIONALE.md): why TigerFetch uses Go, the migration background and naming compatibility.
*   [`docs/SYSTEM_DESIGN.md`](docs/SYSTEM_DESIGN.md) — canonical architecture document: C1/C2/C3 views, data model, per-pipeline ingestion semantics, concurrency model, observability.
*   [`docs/SOURCES-TIERED.md`](docs/SOURCES-TIERED.md) — tiered plan for intel sources beyond the core NVD / EPSS / KEV / RSS set. **Tier-1 complete** as of v1.4.0 (OSV / GHSA / URLhaus / ThreatFox / MalwareBazaar / Nuclei / MSF all shipped).
*   [`docs/DATA_INSIGHTS.md`](docs/DATA_INSIGHTS.md) — analytical snapshots of the live lake: risk pyramid, sleeper-CVE patterns, threat velocity, weakness classes.
*   [`docs/FEED_VALIDATION.md`](docs/FEED_VALIDATION.md) — how to diagnose a flaky RSS/Atom feed.
*   [`docs/TIGERFETCH_CLI.md`](docs/TIGERFETCH_CLI.md) — Python CLI (`scripts/tigerfetch_cli.py`) for SOC-style triage against the PostgREST surface.
*   [`docs/API_ENDPOINTS_SECURITY_TRIAGE_GUIDE.md`](docs/API_ENDPOINTS_SECURITY_TRIAGE_GUIDE.md) — endpoint-by-endpoint guide to the PostgREST `api` schema with security/triage commentary.
*   [`cybersecurity_feeds.md`](cybersecurity_feeds.md) — licence-compliant feed list (public-domain / OGL v3.0 / CC-permissive).
*   [`CHANGELOG.md`](CHANGELOG.md) — semver-tracked release notes.
