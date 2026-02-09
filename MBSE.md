# Tiger2Go — System Summary (MBSE 2.0 Aligned)

## 1. Strategic Justification & NIS2 Market Drivers

### 1.1 Why This Capability Exists

Organisations that provide services to **Critical National Infrastructure (CNI)** operators — energy, transport, health, digital infrastructure, water, finance — face a dual challenge:

1. **Threat-landscape velocity.** The volume of disclosed vulnerabilities exceeded 29,000 CVEs in 2023 and continues to accelerate. No single feed covers the full picture; actionable intelligence is scattered across government CERTs, vendor advisories, exploit databases, and community analysis. Manual aggregation is unsustainable.
2. **Regulatory obligation.** The **EU NIS2 Directive** (Directive 2024/2555), transposed into Member State law from October 2024, extends cybersecurity duties beyond CNI operators themselves to their **supply chain and service providers**. Articles 21 and 23 impose explicit requirements for vulnerability handling, incident reporting, and supply-chain risk management — all of which depend on timely, structured threat intelligence.

Tiger2Go exists to close this gap: a self-hosted, auditable, continuously-running OSINT aggregation engine that feeds downstream security operations with normalised, enriched vulnerability data — at machine speed and at a fraction of the cost of commercial threat-intel platforms.

### 1.2 NIS2 Compliance Mapping

The table below maps Tiger2Go capabilities to specific NIS2 obligations relevant to **providers of services to essential and important entities**:

| NIS2 Article / Obligation | Requirement Summary | Tiger2Go Capability | How It Helps |
|:---|:---|:---|:---|
| **Art. 21(2)(a)** — Risk analysis & information system security policies | Entities must adopt policies for risk analysis including vulnerability management | C1 (RSS Ingestion), C2 (NVD), C3 (KEV) | Continuous aggregation of vulnerability disclosures across 22+ authoritative sources provides the raw material for risk-based prioritisation |
| **Art. 21(2)(d)** — Supply-chain security | Security of the supply chain, including security-related aspects of relationships between each entity and its direct suppliers or service providers | C2 (NVD enrichment), C4 (EPSS scoring) | CVE-level enrichment with CVSS severity and EPSS exploit-probability scores enables supply-chain partners to prioritise shared-component vulnerabilities |
| **Art. 21(2)(e)** — Vulnerability handling and disclosure | Vulnerability handling and disclosure, including coordinated vulnerability disclosure | C2 (NVD), C3 (CISA KEV), C7 (QA views) | Automated ingestion of NVD and KEV ensures known-exploited vulnerabilities are surfaced within hours; QA views provide auditable evidence of coverage |
| **Art. 21(2)(g)** — Basic cyber hygiene practices and training | Cyber hygiene and cybersecurity training | C5 (Observability), C6 (REST API) | Dashboards and API endpoints make threat data accessible to non-specialist teams for awareness and training |
| **Art. 23** — Reporting obligations | Significant incidents must be reported to CSIRTs/competent authorities within defined timeframes | C1 (multi-CERT feeds), C3 (KEV) | Near-real-time ingestion from CISA, CERT-EU, NCSC, JPCERT provides early warning that accelerates incident triage and reporting timelines |
| **Art. 29** — Information sharing | Voluntary cybersecurity information-sharing arrangements | C6 (PostgREST API), Data model (JSONB) | Structured, machine-readable data store enables automated sharing with sector ISACs, partners, and regulators via standard API interfaces |
| **Recital 58 / Art. 21(3)** — Proportionality & state of the art | Measures shall take into account the state of the art, relevant standards, and cost of implementation | Full system | Open-source, self-hosted, config-driven — achieves comparable coverage to commercial platforms at minimal operational cost |

### 1.3 Value Proposition (OSINT Threat Intelligence)

| Dimension | Commercial TI Platform | Tiger2Go |
|:---|:---|:---|
| **Annual cost** | £50k–£250k+ per seat/tier | Infrastructure cost only (~£5–15/month on Fly.io + managed Postgres) |
| **Data sovereignty** | Vendor-controlled SaaS; data leaves your perimeter | Self-hosted; data never leaves your infrastructure |
| **Transparency** | Black-box scoring and enrichment | Full source code; every ingestion step is auditable and logged |
| **Customisability** | Vendor roadmap-dependent | Add a feed in 3 lines of TOML; extend enrichment in Go |
| **NIS2 audit evidence** | Vendor attestation letters | Direct database access to ingestion timestamps, cursors, coverage views |
| **Vendor lock-in** | High switching costs | Zero lock-in; PostgreSQL + standard REST API |

### 1.4 Target Operating Model

Tiger2Go is designed to sit at **Layer 1 (Collection & Normalisation)** of a defence-in-depth threat intelligence programme:

```
┌──────────────────────────────────────────────────────┐
│  Layer 4: Decision Support                           │
│  (Risk dashboards, board reporting, NIS2 evidence)   │
├──────────────────────────────────────────────────────┤
│  Layer 3: Analysis & Correlation                     │
│  (SIEM rules, SOAR playbooks, analyst triage)        │
├──────────────────────────────────────────────────────┤
│  Layer 2: Enrichment & Scoring                       │
│  (CVSS, EPSS, KEV flags, asset-context join)         │
├──────────────────────────────────────────────────────┤
│  Layer 1: Collection & Normalisation  ◀── Tiger2Go   │
│  (RSS/Atom, NVD API, KEV JSON, EPSS bulk)            │
└──────────────────────────────────────────────────────┘
```

Downstream consumers (SIEM, ticketing, GRC tools) query Tiger2Go's REST API or connect directly to PostgreSQL, inheriting structured, de-duplicated, time-stamped intelligence without needing to manage individual feed integrations themselves.

---

## 2. System Purpose & Operational Context

**Tiger2Go** (`tigerfetch`) is a high-performance **OSINT vulnerability ingestor** written in Go. It continuously aggregates, normalises, and enriches cybersecurity intelligence from heterogeneous public sources into a single PostgreSQL data store, making it queryable via a RESTful API layer (PostgREST) and observable through Prometheus/Grafana dashboards.

The system was migrated from an earlier Rust implementation to Go for ecosystem alignment, broader contributor access, and simpler deployment.

**Stakeholders served:** SOC analysts, vulnerability management teams, threat-intelligence engineers, and automated downstream consumers (SIEM, ticketing, dashboards).

---

## 3. Capability Decomposition

| Capability | Description | Status |
|:---|:---|:---|
| **C1 – RSS/Atom Ingestion** | Parallel fetch of ~20+ cybersecurity RSS/Atom feeds (CISA, NCSC, SANS, vendor advisories, threat-intel blogs, news) with HTML sanitisation | ✅ Operational |
| **C2 – NVD CVE Enrichment** | Windowed (120-day chunk) ingestion of NIST NVD v2.0 API data with API-key-aware rate limiting and CVSS score extraction | ✅ Operational |
| **C3 – CISA KEV Sync** | Full-catalog sync of the Known Exploited Vulnerabilities list with cursor-based change detection | ✅ Operational |
| **C4 – EPSS Scoring** | Daily bulk ingestion (~300k rows/day) of FIRST.org Exploit Prediction Scoring System data into a partitioned table | ✅ Operational |
| **C5 – Observability** | Prometheus metrics endpoint (`/metrics`), health check (`/healthz`), Grafana dashboards | ✅ Operational |
| **C6 – REST API** | PostgREST auto-generates a RESTful API from the PostgreSQL schema (views, tables) | ✅ Operational |
| **C7 – Data Quality Analytics** | 10 SQL views for feed coverage, gap analysis, and triage reporting | ✅ Operational |

---

## 4. Functional Architecture (Data Flow)

```
┌─────────────────────────────────────────────────────────────────┐
│                      External Data Sources                      │
│  RSS/Atom Feeds │ NVD v2.0 API │ CISA KEV JSON │ FIRST.org EPSS│
└───────┬─────────┴──────┬────────┴──────┬────────┴──────┬────────┘
        │                │               │               │
        ▼                ▼               ▼               ▼
  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
  │ Ingestor │    │NvdRunner │    │KevRunner │    │EpssRunner│
  │(gofeed + │    │(windowed │    │(catalog  │    │(paginated│
  │bluemonday│    │ paging + │    │  cursor) │    │ COPY bulk│
  │  parser) │    │ backoff) │    │          │    │  insert) │
  └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘
       │               │               │               │
       ▼               ▼               ▼               ▼
  ┌────────────────────────────────────────────────────────────┐
  │                    PostgreSQL (pgx/v5)                      │
  │  archive │ current │ cve_raw │ cve_enriched │ epss_daily   │
  │          │         │         │              │ (partitioned)│
  │  ingest_state (cursor tracking per source)                 │
  │  10 QA/analytics views (v_feed_coverage_summary, etc.)     │
  └────────────┬───────────────────────┬───────────────────────┘
               │                       │
               ▼                       ▼
         ┌───────────┐          ┌─────────────┐
         │ PostgREST │          │ Prometheus  │
         │ (REST API)│          │  + Grafana  │
         └───────────┘          └─────────────┘
```

---

## 5. Logical Architecture (Go Module Structure)

The codebase follows the **Standard Go Project Layout** with clean separation of concerns:

| Package | Responsibility |
|:---|:---|
| `cmd/tigerfetch/main.go` | **Composition root** — loads config, runs migrations, wires workers, starts metrics server, orchestrates graceful shutdown via OS signals |
| `internal/config/` | Configuration loading via Viper (TOML file + env vars). Typed structs for all subsystems (NVD, EPSS, KEV, feeds) |
| `internal/db/` | Connection pooling (`pgxpool`, 25 max / 2 min conns) and schema migrations via Goose |
| `internal/ingestor/` | Generic RSS/Atom pipeline — fetch → sanitise (bluemonday UGC policy) → transactional dual-write to `archive` (append-only) + `current` (upsert) |
| `internal/cve/nvd.go` | NVD v2.0 API client — 120-day windowed pagination, exponential backoff on 429/503, batched `pgx.Batch` writes to `cve_enriched`, CVSS v3.1/v3.0 score extraction |
| `internal/cve/kev.go` | CISA KEV catalog client — full-catalog fetch, cursor-based skip logic, batch upsert to `cve_enriched` |
| `internal/cve/epss.go` | FIRST.org EPSS client — paginated JSON API, auto-partition creation (monthly), high-throughput `COPY FROM` bulk insert (~300k rows) |
| `migrations/` | 9 Goose-compatible SQL migrations covering schema evolution from initial tables through partitioned EPSS and QA views |

**Concurrency model:** The main loop runs all four worker types (RSS, NVD, KEV, EPSS) concurrently via `sync.WaitGroup`. RSS feeds are additionally bounded by a semaphore (concurrency = 3) to avoid overwhelming upstream sources.

The application’s main loop launches four different types of background workers at the same time:

    RSS/Atom feed ingestor
    NVD (National Vulnerability Database) fetcher
    KEV (CISA Known Exploited Vulnerabilities) fetcher
    EPSS (Exploit Prediction Scoring System) fetcher

These workers are started as separate goroutines (lightweight threads in Go), and their lifecycles are coordinated using a sync.WaitGroup. This ensures the main process can wait for all workers to finish before proceeding or shutting down.

For the RSS/Atom feed ingestor, there may be many feeds to fetch. To avoid making too many simultaneous requests (which could overload or get blocked by upstream servers), the code uses a semaphore pattern:

Only three RSS feeds are fetched in parallel at any given time.
When a feed fetch starts, it acquires a slot in the semaphore; when it finishes, it releases the slot, allowing another feed to start.

This approach balances efficiency (parallelism) with politeness (not overwhelming external sources), and ensures all ingestion tasks run concurrently but safely.

---

## 6. Physical Architecture & Deployment

| Layer | Technology | Notes |
|:---|:---|:---|
| **Runtime** | Go 1.24, multi-stage Docker (builder: `golang:1.24-bookworm` → runtime: `debian:bookworm-slim`) | Non-root container user, minimal image |
| **Database** | PostgreSQL 14+ | Table partitioning (EPSS by month), JSONB storage, UUID PKs, array columns |
| **API Gateway** | PostgREST | Auto-generated REST from schema; row-level limits (1000 max), anonymous role |
| **Observability** | Prometheus → Grafana (with Infinity + LLM plugins) | 15s scrape interval |
| **Admin** | pgAdmin 4 | Available on port 5050 |
| **Cloud** | Fly.io (`ams` region, 512 MB / 1 shared CPU, always-on) | Configured via `fly.toml` |
| **Orchestration** | Docker Compose (6 services) | `tigerfetch`, `postgrest`, `prometheus`, `grafana`, `pgadmin`, `db` (optional) |

---

## 7. Data Model (Key Entities)

| Table | Purpose | Key Properties |
|:---|:---|:---|
| `archive` | Immutable append-only record of every feed item ever seen | UUID PK, unique GUID index, text arrays for categories |
| `current` | Latest state of each feed item (upsert on GUID) | Same schema as archive, upsert semantics |
| `cve_raw` | Raw upstream CVE payloads (MITRE source) | Composite PK `(cve_id, source)`, JSONB storage |
| `cve_enriched` | Enriched CVE records (NVD, CISA-KEV) with indexed scores | CVSS base + EPSS numeric columns, JSONB full record |
| `epss_daily` | Daily EPSS score history (partitioned by month) | ~300k rows/day, `COPY FROM` optimised |
| `ingest_state` | Cursor/checkpoint per data source | Enables idempotent, resumable ingestion |

**Analytical views:** 10 pre-built views (`v_feed_coverage_summary`, `v_epss_movers_24h`, `v_missing_both_per_feed`, etc.) provide instant data-quality and threat-triage dashboards.

---

## 8. Interface Catalogue

| Interface | Protocol | Direction | Rate Limits |
|:---|:---|:---|:---|
| RSS/Atom Feeds (×22 active) | HTTP GET → XML | Inbound | Semaphore-bounded (3 concurrent) |
| NIST NVD v2.0 | HTTPS GET → JSON | Inbound | 5 req/30s (no key) · 50 req/30s (with key) |
| CISA KEV | HTTPS GET → JSON | Inbound | On-demand (cursor-gated) |
| FIRST.org EPSS | HTTPS GET → JSON | Inbound | Paginated, 100ms inter-page delay |
| PostgreSQL | TCP/5432 (pgx/v5 pool) | Internal | 25 max / 2 min connections |
| Prometheus `/metrics` | HTTP GET | Outbound (scrape) | 15s interval |
| Health `/healthz` | HTTP GET | Outbound (probe) | On-demand |
| PostgREST REST API | HTTP → SQL | Outbound (consumers) | 1000 row max per response |

---

## 9. Quality & Verification (DevSecOps Pipeline)

The `Makefile` encodes a `make all` pipeline that runs before every commit:

| Stage | Tool | Purpose |
|:---|:---|:---|
| **Lint** | `golangci-lint` v2.8.0 | Static analysis, style enforcement |
| **SCA** | `govulncheck` v1.1.4 | Known-vulnerability scan of compiled binary |
| **SAST** | `gosec` v2.22.11 | Security-focused static analysis |
| **Test** | `go test -race` | Unit + integration tests with race detection |
| **Container Scan** | Trivy | Image-level vulnerability scanning |

Tooling is **repo-local** (installed to `./bin`), version-pinned, and auto-bootstrapped on first run. `CODING_STANDARDS.md` enforces conventional commits, single-purpose branches, and mandatory pre-merge quality gates.

---

## 10. Configuration & Extensibility

The system is configured entirely through `Config.toml` (with environment-variable overrides via Viper). Adding a new feed source requires only appending a `[[feeds]]` block — no code changes. Each specialised subsystem (NVD, KEV, EPSS) can be independently enabled/disabled and tuned (poll interval, page size, API keys). Content-length limits are configurable to prevent unbounded storage growth.

Currently **22 feeds are active** across 7 categories:

| Category | Examples |
|:---|:---|
| Official Government | CISA Alerts, CISA Advisories, UK NCSC, CERT-EU, JPCERT, Debian Security |
| Vendor Security | Cisco, Ubuntu |
| Threat Intelligence | Google TAG, Recorded Future, Cisco Talos, Palo Alto Unit42 |
| Exploit Databases | Exploit-DB, Google Project Zero |
| Malware / IOC | MISP Project |
| DFIR | The DFIR Report |
| Cybersecurity News | Krebs on Security, BleepingComputer, The Hacker News, SecurityWeek, DarkReading |

An additional ~15 feeds are documented but disabled with inline rationale (404s, TLS issues, Cloudflare bot protection, API-key requirements).

---

## 11. Traceability Matrix (MBSE 2.0 Alignment)

| MBSE 2.0 Concern | Tiger2Go Artefact |
|:---|:---|
| **Strategic Justification** | NIS2 Art. 21/23 compliance for CNI service providers; OSINT cost advantage over commercial TI, Section 1 |
| **Operational Need** | Unified, normalised cybersecurity intelligence lake |
| **Stakeholder Requirements** | Config-driven feed selection, REST API for downstream consumers, daily EPSS trend analysis |
| **Regulatory Requirements** | NIS2 vulnerability handling (Art. 21(2)(e)), supply-chain security (Art. 21(2)(d)), reporting (Art. 23), Section 1.2 |
| **System Requirements** | Idempotent ingestion, cursor-based resumability, rate-limit compliance, graceful shutdown |
| **Functional Architecture** | 4 concurrent worker types, dual-write pattern (archive + current), Section 3 diagram |
| **Logical Architecture** | Standard Go Project Layout, `internal/` package boundaries, Section 4 |
| **Interface Definitions** | NVD v2.0 JSON, CISA KEV JSON, FIRST.org EPSS JSON, RSS/Atom XML, Prometheus exposition format, Section 7 |
| **Physical Architecture** | Containerised Go binary + PostgreSQL + PostgREST on Fly.io, Section 5 |
| **Data Architecture** | 6 tables (2 feed, 2 CVE, 1 EPSS, 1 state) + 10 QA views, Section 6 |
| **V&V** | Automated lint → SCA → SAST → race-detected tests → container scan, Section 8 |
| **Configuration Management** | Goose migrations, conventional commits, single-purpose branching, `CODING_STANDARDS.md` |

---

## 12. Key Design Decisions

| Decision | Rationale |
|:---|:---|
| **Dual-write (archive + current)** | Immutable audit trail in `archive`; fast lookups on latest state in `current` |
| **JSONB storage for CVE data** | Preserves full upstream fidelity; indexed scalar columns (CVSS, EPSS) enable fast queries |
| **Monthly partitioning for EPSS** | ~300k rows/day requires partition pruning for query performance |
| **Cursor-based checkpointing** | Enables idempotent restarts; no duplicate ingestion after crash/redeploy |
| **Semaphore-bounded RSS concurrency** | Prevents overwhelming upstream feed providers while maintaining parallelism |
| **Exponential backoff on NVD** | Respects NVD rate limits (429/503); avoids IP bans |
| **Rust → Go migration** | Broader contributor pool, simpler dependency management, faster compile times |
| **PostgREST over custom API** | Zero-code API generation from schema; views become endpoints automatically |
| **Repo-local tooling** | Reproducible builds; no global tool version conflicts |

---

## 13. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|:---|:---|:---|:---|
| **NIS2 non-compliance (Art. 21 vulnerability handling)** | Medium | Critical | Tiger2Go provides automated, auditable ingestion of NVD, KEV, and EPSS; QA views generate evidence of coverage for regulators |
| **NIS2 reporting timeline breach (Art. 23)** | Medium | Critical | Near-real-time ingestion from multi-CERT feeds (CISA, CERT-EU, NCSC) accelerates triage; API enables automated incident-detection pipelines |
| **Loss of OSINT capability to commercial vendor lock-in** | Medium | High | Open-source, self-hosted, PostgreSQL-based — no single-vendor dependency; switching cost is zero |
| Upstream feed URL breakage | High (observed Dec 2025) | Medium | Feeds disabled with inline notes; periodic validation script (`validate_feeds.sh`) |
| NVD API rate limiting / outage | Medium | Medium | Exponential backoff, API key support, cursor-based resume |
| EPSS bulk data volume growth | Low | Medium | Monthly partitioning, configurable page sizes |


---

*Generated: 8 February 2026*
