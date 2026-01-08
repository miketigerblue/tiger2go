#!/usr/bin/env bash
set -euo pipefail

# Validate all feeds from a config and then diagnose failures.
#
# Usage:
#   scripts/validate_feeds.sh [Config.toml.fly]
#
# Outputs:
#   - feeds_report.json (machine-readable)
#   - feed_validation_report.md (human summary)
#   - feed_diagnose_failures.log (diagnose output for failing feeds)

CONFIG_PATH="${1:-Config.toml.fly}"

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Config not found: $CONFIG_PATH" >&2
  exit 2
fi

echo "==> Running validate_feeds for: $CONFIG_PATH"
# note: validate_feeds exits 2 if any feed fails; keep going so we can diagnose.
set +e
cargo run --quiet --bin validate_feeds -- --config "$CONFIG_PATH" --json feeds_report.json
VALIDATE_RC=$?
set -e

echo "==> validate_feeds exit code: $VALIDATE_RC"

if [[ ! -f feeds_report.json ]]; then
  echo "feeds_report.json was not created; aborting" >&2
  exit 2
fi

echo "==> Writing markdown summary (feed_validation_report.md)"
python3 - <<'PY'
import json
from pathlib import Path

with open('feeds_report.json') as f:
    data = json.load(f)

fails = [d for d in data if not d['ok']]

lines = []
lines.append('# Feed validation report\n')
lines.append(f"Total feeds: {len(data)}  ")
lines.append(f"OK: {len([d for d in data if d['ok']])}  ")
lines.append(f"FAIL: {len(fails)}\n")

lines.append('## Failures\n')
for d in fails:
    lines.append(f"### {d['name']}")
    lines.append(f"- URL: `{d['url']}`")
    lines.append(f"- Kind: `{d.get('error_kind')}`")
    if d.get('status') is not None:
        lines.append(f"- HTTP status: `{d.get('status')}`")
    if d.get('content_type'):
        lines.append(f"- Content-Type: `{d.get('content_type')}`")
    snip = (d.get('snippet') or '')
    if snip:
        snip = snip.replace('\n',' ')
        if len(snip) > 240:
            snip = snip[:240] + '…'
        lines.append(f"- Snippet: `{snip}`")
    lines.append('')

Path('feed_validation_report.md').write_text('\n'.join(lines))
PY

echo "==> Failed feeds (name | url)"
python3 - <<'PY'
import json
with open('feeds_report.json') as f:
    data = json.load(f)
for d in data:
    if not d['ok']:
        print(f"- {d['name']} | {d['url']}")
PY

echo "==> Running diagnose_feed for each failing URL (feed_diagnose_failures.log)"
: > feed_diagnose_failures.log
# NOTE: diagnose_feed prints to stderr (eprintln!), so we must capture stderr too.
python3 - <<'PY' 2>&1 | tee -a feed_diagnose_failures.log
import json, subprocess

with open('feeds_report.json') as f:
    data = json.load(f)

fails = [d for d in data if not d['ok']]

for d in fails:
    name = d['name']
    url = d['url']
    print(f"\n===== {name} =====\nURL: {url}\n")
    subprocess.run(
        # Capture both stdout+stderr from diagnose_feed.
        ['bash','-lc', f"cargo run --quiet --bin diagnose_feed -- {url!r} 2>&1"],
        check=False,
    )
PY

cat <<'TXT'

==> Optional: candidate replacement URLs to test manually

  Cisco Talos:
    https://blog.talosintelligence.com/rss/

  JPCERT (try these):
    https://www.jpcert.or.jp/rss/jpcert-all.rdf
    https://www.jpcert.or.jp/rss/jpcert.rdf
    https://www.jpcert.or.jp/rss/whatsnew.rdf

  URLhaus (maybe moved):
    https://urlhaus.abuse.ch/feeds/rss/

  Google Cloud topics (replace HTML app-shell URLs):
    https://cloud.google.com/feeds/blog/topics/security.xml
    https://cloud.google.com/feeds/blog/topics/threat-intelligence.xml

If you paste the diagnose output for any replacement candidates that still fail,
I can draft an updated Config.toml.fly patch.
TXT

# Preserve validate_feeds exit code semantics (useful in CI)
exit "$VALIDATE_RC"
