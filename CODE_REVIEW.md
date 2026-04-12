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

- [ ] **Prometheus label cardinality explosion (DoS vector)** — `internal/metrics/middleware.go:39`
  Raw `r.URL.Path` used as metric label. Unbounded time series possible.
  **Fix:** Map paths to a fixed set (`/metrics`, `/healthz`, `other`).

- [ ] **Pool closed while goroutines still active** — `cmd/tigerfetch/main.go:72, 218-227`
  `defer pool.Close()` runs on shutdown but worker goroutines have no WaitGroup.
  **Fix:** Add `sync.WaitGroup` for all worker goroutines; wait before closing pool.

- [ ] **Missing HTTP IdleTimeout** — `cmd/tigerfetch/main.go:87-92`
  No `IdleTimeout` — clients can hold connections indefinitely.
  **Fix:** Add `IdleTimeout: 30 * time.Second`.

- [ ] **Negative poll interval causes tight loop** — `cmd/tigerfetch/main.go:111-166`
  Duration parsing checks `== 0` but not `< 0`.
  **Fix:** Validate `> 0`.

---

## P2 — Correctness / data quality

- [ ] **`time.After()` leak in ticker loops** — `cmd/tigerfetch/main.go:119-205`
  Each iteration creates a new `time.After` channel. Unfired timers accumulate until GC.
  **Fix:** Use `time.NewTimer` with `Reset()`.

- [ ] **DB transaction uses parent ctx, not timeout ctx** — `internal/ingestor/ingestor.go:45-46, 126`
  Feed fetch uses 30s timeout but DB transaction uses unbounded parent ctx.
  **Fix:** Use same timeout context or add DB-specific timeout.

- [ ] **Invalid migration filename** — `migrations/20250532_create_cve_enriched.sql`
  May 32 doesn't exist. Lexicographic sorting works but confusing.

- [ ] **Duplicate migration** — `migrations/20250601` and `20250602` both create `ingest_state` with identical SQL.

---

## P3 — Testing gaps

- [ ] **No unit tests for:** `internal/config/`, `internal/db/`, `internal/metrics/`, `cmd/tigerfetch/`

- [ ] **NVD `fetchWithRetry` has zero test coverage** — most complex control flow in codebase.

- [ ] **XSS sanitization test doesn't verify sanitization ran** — `internal/ingestor/ingestor_test.go:235-267`
  Asserts `NotContains("<script>")` but test data uses entity-encoded tags — passes without sanitization.
