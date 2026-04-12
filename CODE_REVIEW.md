# Code Review — Priority Bug Fixes & Improvements

Reviewed: 2026-04-04

---

## P0 — Bugs that will cause incorrect behavior now

- [x] **Batch exec count mismatch in NVD and KEV** — `internal/cve/nvd.go`, `internal/cve/kev.go`
  Exec loop iterated `len(items)` but skipped `json.Marshal` failures meant fewer statements queued.
  **Fixed:** Track `queued` counter, iterate on that instead.

- [x] **EPSS pagination masks partial failure as success** — `internal/cve/epss.go`
  If a mid-pagination fetch failed, the loop broke but returned nil with "success" metric.
  **Fixed:** Return wrapped error instead of breaking silently.

- [x] **NVD retry loop ignores context cancellation** — `internal/cve/nvd.go`
  `fetchWithRetry` used `time.Sleep(backoff)` in an infinite loop, ignoring ctx cancellation.
  **Fixed:** Use `select` on `ctx.Done()` / `time.After`, cap retries at 10.

- [x] **`url.Parse` error discarded, nil deref possible** — `internal/cve/nvd.go`
  `u, _ := url.Parse(baseURL)` could panic on nil.
  **Fixed:** Check and return error.

---

## P1 — Will cause problems under load or attack

- [x] **Prometheus label cardinality explosion (DoS vector)** — `internal/metrics/middleware.go`
  Raw `r.URL.Path` used as metric label. Unbounded time series possible.
  **Fixed:** `normalizePath()` maps to fixed set (`/metrics`, `/healthz`, `other`).

- [x] **Pool closed while goroutines still active** — `cmd/tigerfetch/main.go`
  `defer pool.Close()` ran on shutdown but worker goroutines had no WaitGroup.
  **Fixed:** Added `sync.WaitGroup` for all workers; `workers.Wait()` before pool close.

- [x] **Missing HTTP IdleTimeout** — `cmd/tigerfetch/main.go`
  No `IdleTimeout` — clients could hold connections indefinitely.
  **Fixed:** Added `IdleTimeout: 30 * time.Second`.

- [x] **Negative poll interval causes tight loop** — `cmd/tigerfetch/main.go`
  Duration parsing checked `== 0` but not `< 0`.
  **Fixed:** Combined check: `err != nil || interval <= 0` triggers default.

---

## P2 — Correctness / data quality

- [x] **`time.After()` leak in ticker loops** — `cmd/tigerfetch/main.go`
  Each iteration created a new `time.After` channel. Unfired timers accumulated until GC.
  **Fixed:** Replaced with `time.NewTimer` + `Reset()`, `defer ticker.Stop()`.

- [x] **DB transaction uses parent ctx, not timeout ctx** — `internal/ingestor/ingestor.go`
  Feed fetch used 30s timeout but DB transaction used unbounded parent ctx.
  **Fixed:** Renamed to `opCtx`, passed to both HTTP fetch and `processItem`.

- [x] **Invalid migration filename** — `migrations/20250532_create_cve_enriched.sql`
  May 32 doesn't exist. Lexicographic sorting works but confusing.
  **Won't fix:** Already applied to live DBs; renaming would break Goose version tracking.

- [x] **Duplicate migration** — `migrations/20250601` and `20250602` both create `ingest_state` with identical SQL.
  **Won't fix:** Already reconciled by `20250913_fix_checksums.sql`. Harmless due to `IF NOT EXISTS`.

---

## P3 — Testing gaps

- [ ] **No unit tests for:** `internal/config/`, `internal/db/`, `internal/metrics/`, `cmd/tigerfetch/`

- [ ] **NVD `fetchWithRetry` has zero test coverage** — most complex control flow in codebase.

- [ ] **XSS sanitization test doesn't verify sanitization ran** — `internal/ingestor/ingestor_test.go:235-267`
  Asserts `NotContains("<script>")` but test data uses entity-encoded tags — passes without sanitization.
