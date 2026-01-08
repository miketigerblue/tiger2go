# Tiger2Go - TigerFetch (Go Port)

`tigerfetch` is a high-performance OSINT vulnerability ingestor rewritten in Go. It aggregates security advisories from RSS/Atom feeds, enriches them with official CVE data (NVD, CISA KEV), and tracks daily EPSS scores.

## 🚀 Features

*   **RSS/Atom Ingestion**: Parallel fetching of security feeds using `gofeed` with `bluemonday` sanitization.
*   **CVE Enrichment**:
    *   **NVD**: Windowed fetching of CVE details (120-day chunks) with API key support and rate limiting (v2.0 API).
    *   **CISA KEV**: Synced storage of the Known Exploited Vulnerabilities catalog.
    *   **EPSS**: Bulk ingestion of daily Exploit Prediction Scoring System scores (~300k records/day).
*   **Database**: PostgreSQL storage using `pgx/v5` connection pooling.
*   **Migrations**: Embedded schema migrations using `pressly/goose`.
*   **Observability**: Prometheus metrics (`/metrics`) and Health checks (`/healthz`).

## 🛠️ Build & Run

### Prerequisites
*   Go 1.24+
*   PostgreSQL 14+

### Building

```bash
# Build the binary
go build -o tigerfetch ./cmd/tigerfetch
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
| `[nvd]` | `api_key` | Optional NVD API Key for higher rate limits |
| `[epss]` | `enabled` | Toggle EPSS ingestion (files are large) |

## 🏗️ Project Structure

*   `cmd/tigerfetch`: Application entry point.
*   `internal/config`: Viper configuration loading.
*   `internal/db`: Database connection and migration logic.
*   `internal/ingestor`: RSS/Atom feed processing logic.
*   `internal/cve`: Specialized modules for NVD, KEV, and EPSS.
*   `migrations/`: SQL migration files (Goose compatible).
