<p align="center">
  <img src="tigerfetch_hunt_the_signal.png" alt="TigerFetch — hunt the signal" width="400" />
</p>

<h1 align="center">Tiger2Go - TigerFetch</h1>

<p align="center"><em>hunt_the_signal()</em></p>

> **Mission:** Provide a reliable, observable, single-binary cybersecurity OSINT ingestion service that continuously collects, normalises, and stores threat intelligence from public feeds and vulnerability databases — giving security teams a queryable data lake for risk-informed decision making.

---

## Why a Rust → Go port?

Most ports you see out in the wild go **Go → Rust** (performance, memory safety signalling, “serious systems” vibes).

This project goes the other way on purpose.

`tiger2go` repo is a Go port of **tigerfetch**, originally written in Rust. The goal here is not “Go is better than Rust”. It’s that **the dominant problem in this system is not memory ownership** - it’s *operational ingestion*:

- high-volume I/O (RSS/Atom, NVD JSON, KEV, daily EPSS)
- untrusted inputs (feeds are user input in a trenchcoat)
- concurrency + retries + backoff + rate limits
- metrics, health, and long-running process behaviour
- boring reliability under real-world failure modes

Go is simply a great fit for that shape:

goroutines and a mature runtime make it easy to coordinate concurrent workers,
and the resulting code tends to be globally readable and straightforward to operate.

Rust is still excellent - especially when memory ownership and correctness under adversarial conditions *is* the main fight. In this system, that fight is mostly elsewhere: scheduling, ingestion hygiene, and observability.

So the port direction is less “downgrade” and more **optimising for shipping and operating**. 

A practical side-effect: the original Rust implementation had clear boundaries and explicit data flow. That makes the port tractable (and reviewable), because the architecture maps cleanly to Go.

If you’re curious about the intended “layering” philosophy:

- **Rust** shines for foundations (parsers, crypto, runtimes, very hot paths)
- **Go** shines for control planes (ingestors, schedulers, services, metrics)
- **Python** often shines for reasoning layers (enrichment, ML, semantic glue)

`tiger2go` deliberately sits in that “control plane” zone.

### Design focus

Data sources → ingestion → normalisation → storage → downstream analysis

- Sources: RSS/Atom, NVD, CISA KEV, EPSS
- Ingestion: concurrent workers, rate limiting, retries/backoff
- Hygiene: sanitisation, validation, idempotency/dedupe
- Ops: `/metrics`, `/healthz`, migrations, deployability



## 🚀 Features

*   **RSS/Atom Ingestion**: Parallel fetching of security feeds using `gofeed` with `bluemonday` sanitization.
*   **CVE Enrichment**:
    *   **NVD**: Windowed fetching of CVE details (120-day chunks) with API key support and rate limiting (v2.0 API).
    *   **CISA KEV**: Synced storage of the Known Exploited Vulnerabilities catalog.
    *   **EPSS**: Bulk ingestion of daily Exploit Prediction Scoring System scores (~300k records/day).
*   **Database**: PostgreSQL storage using `pgx/v5` connection pooling.
*   **Migrations**: Embedded schema migrations using `pressly/goose`.
*   **Observability**: Prometheus metrics (`/metrics`), health checks (`/healthz`), and two provisioned Grafana dashboards (operational + threat intelligence).
*   **Grafana Dashboards**:
    *   **TigerFetch Operations** ~30 Prometheus-powered panels: feed health, NVD/EPSS/KEV pipeline status, upstream latency, DB pool, Go runtime.
    *   **Threat Intelligence** ~20 SQL-powered panels: EPSS top 25, CVSS x EPSS danger zone, NVD severity landscape, CISA KEV catalog, feed content coverage.

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

Configuration is handled via `Config.toml` and environment variables. Key sections:

| Section | Key | Description |
| :--- | :--- | :--- |
| Global | `database_url` | Postgres DSN connection string |
| Global | `server_bind` | Host:Port for metrics server (default `0.0.0.0:9101`) |
| Global | `ingest_interval` | Feed polling interval (default `1h`) |
| `[[feeds]]` | `name`, `url`, `feed_type`, `tags` | RSS/Atom feed sources |
| `[nvd]` | `enabled` | Toggle NVD ingestion |
| `[nvd]` | `api_key` | Optional NVD API key for higher rate limits |
| `[nvd]` | `poll_interval` | NVD polling interval |
| `[nvd]` | `page_size` | Results per NVD API page |
| `[epss]` | `enabled` | Toggle EPSS ingestion (files are large) |
| `[epss]` | `poll_interval` | EPSS polling interval |
| `[epss]` | `page_size` | EPSS API page size |
| `[kev]` | `enabled` | Toggle CISA KEV ingestion |
| `[kev]` | `poll_interval` | KEV polling interval |

## 🏗️ Project Structure

*   `cmd/tigerfetch`: Application entry point.
*   `internal/config`: Viper configuration loading.
*   `internal/db`: Database connection and migration logic.
*   `internal/ingestor`: RSS/Atom feed processing logic.
*   `internal/cve`: Specialized modules for NVD, KEV, and EPSS.
*   `internal/metrics`: Prometheus metric definitions, pgxpool collector, HTTP middleware.
*   `grafana/`: Provisioned Grafana dashboards and datasource configuration.
*   `migrations/`: SQL migration files (Goose compatible).
