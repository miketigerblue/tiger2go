# Feed validation

This repo includes two small helpers for debugging RSS/Atom issues.

## 1) Validate all feeds from a config file

`validate_feeds` loads `[[feeds]]` from a TOML config file and then validates each feed sequentially using the same HTTP client + parsing logic as the real ingestor (`tigerfetch::ingestor::fetch_feed`).

It reports:
- HTTP status and content-type (when available)
- whether the response is HTML (bot protection / JS app shells)
- whether `feed-rs` can parse the document

### Run

```bash
cargo run --bin validate_feeds -- --config Config.toml.fly --json feeds_report.json
```

- Exit code is `0` if all feeds pass.
- Exit code is `2` if *any* feed fails.

`--json -` prints the full JSON report to stdout.

## 2) Diagnose a single feed

`diagnose_feed` is useful when you want to focus on one problematic URL and see a short body snippet.

```bash
cargo run --bin diagnose_feed -- https://example.com/feed.xml
```

## Typical failure modes

- `HttpStatus 404`: URL is stale/changed (replace URL or disable)
- `HttpStatus 403` with "Just a moment…": Cloudflare / bot protection (replace feed or use an API with auth)
- `UnexpectedHtml` with 200: not a raw RSS/Atom endpoint (often a JS app shell); find the real RSS/Atom URL
- `Fetch`: TLS/DNS/timeout from the runtime environment (verify with `curl -v` from same host)
