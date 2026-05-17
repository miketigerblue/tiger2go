<p align="center">
  <img src="../tigerfetch_hunt_the_signal.png" alt="TigerFetch" width="200" />
</p>

# Feed validation

> **Scope:** This document covers **RSS/Atom feed** validation only.
> The Tier-1 *structured* sources (NVD, KEV, EPSS, OSV, GHSA, URLhaus,
> ThreatFox, MalwareBazaar, Nuclei, MSF) don't go through gofeed/bluemonday —
> they hit their own typed APIs and have their own per-ingestor
> `{source}_fetches_total{status}` Prometheus metric for failure
> visibility. Use the `tigerfetch-overview` Grafana dashboard's
> "Tier-1 Threat-Intel Sources" row to see fetch health for those.
>
> **Tooling note:** The `validate_feeds` and `diagnose_feed` CLI tools
> were part of the original Rust implementation and have not yet been
> ported to Go. The Rust commands below are kept for reference. Feed
> validation in the Go codebase is observable via ingestor logs and
> `tigerfetch_feed_fetches_total{status="error"}`.

## 1) Validate all feeds from a config file (Rust — not yet ported)

`validate_feeds` loads `[[feeds]]` from a TOML config file and then validates each feed sequentially using the same HTTP client + parsing logic as the real ingestor.

It reports:
- HTTP status and content-type (when available)
- whether the response is HTML (bot protection / JS app shells)
- whether `feed-rs` can parse the document

### Run (requires Rust toolchain)

```bash
cargo run --bin validate_feeds -- --config Config.toml.fly --json feeds_report.json
```

- Exit code is `0` if all feeds pass.
- Exit code is `2` if *any* feed fails.

`--json -` prints the full JSON report to stdout.

## 2) Diagnose a single feed (Rust — not yet ported)

`diagnose_feed` is useful when you want to focus on one problematic URL and see a short body snippet.

```bash
cargo run --bin diagnose_feed -- https://example.com/feed.xml
```

## Typical failure modes

- `HttpStatus 404`: URL is stale/changed (replace URL or disable)
- `HttpStatus 403` with "Just a moment…": Cloudflare / bot protection (replace feed or use an API with auth)
- `UnexpectedHtml` with 200: not a raw RSS/Atom endpoint (often a JS app shell); find the real RSS/Atom URL
- `Fetch`: TLS/DNS/timeout from the runtime environment (verify with `curl -v` from same host)
