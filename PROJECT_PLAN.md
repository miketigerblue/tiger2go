# Tiger2Go: Rust to Go Migration Plan

This document tracks the conversion of the `tigerfetch` Rust application to a Go-based architecture.

## 1. Project Overview
**Goal:** Rewrite the `tigerfetch` OSINT ingestor in Go.
**Target Stack:**
- **Language:** Go 1.23+
- **Database:** PostgreSQL (pgx driver)
- **Migrations:** Goose
- **Config:** Viper
- **Web/Metrics:** Standard `net/http` + Prometheus client
- **Feed Parsing:** gofeed
- **HTML Sanitization:** bluemonday

## 2. Architecture & Layout
Following the Standard Go Project Layout:
```
.
├── cmd/
│   └── tigerfetch/        # Main application entry point
├── internal/
│   ├── config/            # Configuration loading (Viper)
│   ├── db/                # Database connection & queries (sqlc/pgx)
│   ├── ingestor/          # Core RSS/Atom logic
│   ├── cve/               # Specialized CVE handlers (NVD, EPSS)
│   └── server/            # HTTP server for metrics/healthz
├── migrations/            # SQL migration files (Goose)
├── go.mod
└── go.sum
```

## 3. Implementation Status

### Phase 1: Foundation (Completed)
- [x] Initialize Go Module
- [x] Set up Project Structure
- [x] Configure Database & Migrations (Goose)
- [x] Implement Logging & Error Handling Strategy

### Phase 2: Core Logic (Completed)
- [x] Configuration (Viper)
- [x] RSS/Atom Feed Fetching (gofeed)
- [x] HTML Sanitization (bluemonday)
- [x] Database Repository Layer

### Phase 3: Specialized Modules (Completed)
- [x] EPSS Fetcher (Basic Bulk Insert)
- [x] NVD Fetcher
- [x] KEV Fetcher

### Phase 4: Application & Observability (Completed)
- [x] Metrics (Prometheus) - Port 9101
- [x] Health Checks
- [x] Main Worker Loop (Concurrency/Worker Pool)

## 4. Error Handling Strategy
- **Idiomatic Errors:** Use `fmt.Errorf("context: %w", err)` for wrapping.
- **Custom Errors:** Define sentinel errors in packages where users might need to check specific conditions (e.g., `ErrFeedFetchFailed`).
- **Logging:** Use `log/slog` for structured logging.

## 5. Migration Strategy for Data
- The new Go app will effectively reuse the existing PostgreSQL schema.
- Existing migration files have been adapted for `goose`.
