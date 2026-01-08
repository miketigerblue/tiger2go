# tigerfetch CLI (Python) — security triage utility

This is a small dependency-free Python CLI for interacting with the Tigerfetch PostgREST API.

- Script: `scripts/tigerfetch_cli.py`
- Python: 3.9+ (stdlib only)

It’s designed for **security awareness + triage**:
- `triage` — list recent HIGH/CRITICAL analyses
- `cve` — fetch a CVE profile or generate a patch list
- `campaign` — explore active campaigns and their CVE rollups
- `ioc` — extract IOCs from recent analyses and export to CSV/JSON for hunting

---

## Quick start (venv-first)

Create and activate a venv:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -V
```

Run the CLI:

```bash
python scripts/tigerfetch_cli.py --help
```

Set the base URL (optional):

```bash
export TIGERFETCH_BASE="https://tigerblue-postgrest.fly.dev"
```

If you later add JWT auth:

```bash
export TIGERFETCH_JWT="<token>"
```

---

## Triage (SOC queue)

```bash
# Latest HIGH/CRITICAL
python3 scripts/tigerfetch_cli.py triage --severity CRITICAL HIGH --limit 20

# Last 24 hours, keyword match
python3 scripts/tigerfetch_cli.py triage --since 24h --keyword ransomware --limit 20

# Filter by source
python3 scripts/tigerfetch_cli.py triage --source TheHackerNews --since 7d --limit 50

# JSON output
python3 scripts/tigerfetch_cli.py triage --since 24h --format json | jq '.[0:5]'
```

---

## CVE

```bash
# One CVE profile (table)
python3 scripts/tigerfetch_cli.py cve get CVE-2024-12345

# One CVE profile (JSON)
python3 scripts/tigerfetch_cli.py cve get CVE-2024-12345 --format json | jq '.'

# Patch list: KEV + high EPSS (and mentioned recently)
python3 scripts/tigerfetch_cli.py cve patchlist --in-kev --epss-gte 0.2 --mentioned-since 30d --limit 50

# Patch list: high CVSS
python3 scripts/tigerfetch_cli.py cve patchlist --cvss-gte 9.0 --limit 50
```

---

## Campaigns

```bash
# Latest active exploitation campaigns
python3 scripts/tigerfetch_cli.py campaign latest --kind active_exploitation --limit 20

# Drill into a campaign_key
python3 scripts/tigerfetch_cli.py campaign rollup "active_exploitation:some-key" --limit 100
```

---

## IOC extraction (hunt helper)

```bash
# Extract IOCs from last 24h of CRITICAL/HIGH analyses
python3 scripts/tigerfetch_cli.py ioc --since 24h --severity CRITICAL HIGH --limit 50

# Filter to only values containing 'github'
python3 scripts/tigerfetch_cli.py ioc --since 7d --contains github --limit 200

# Export to CSV and JSON
python3 scripts/tigerfetch_cli.py ioc --since 7d --limit 200 --out-csv iocs.csv --out-json iocs.json
```

---

## Notes / caveats

- This CLI uses **PostgREST Range headers** for safe pagination.
- PostgREST filter operators are powerful; this CLI uses safe defaults (exact match for `source_name`, `ilike` for `title`).
- `key_iocs` is schema-less JSON; the IOC extractor performs best-effort normalization (`ioc_type`, `ioc_value`, etc.).

---

## Next hardening step (optional)

If you decide to lock down endpoints:
- keep `analysis_entries_lite` public for demos
- require JWT for `analysis_entries`, `analysis_search`, `analysis_cve_mentions*`, `campaign_*`, and `number2_*`

The CLI already supports JWT via `--jwt` or `TIGERFETCH_JWT`.
