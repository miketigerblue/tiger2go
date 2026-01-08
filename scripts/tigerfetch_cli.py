#!/usr/bin/env python3
"""tigerfetch_cli.py

A lightweight, dependency-free CLI for querying the Tigerfetch PostgREST API.

Designed for:
- security awareness demos
- SOC triage
- CVE prioritization
- campaign exploration
- IOC extraction for hunting

This tool uses only Python stdlib so you can run it anywhere:
  python3 scripts/tigerfetch_cli.py --help

Auth:
- The PostgREST service can be public/anon. If you add JWT later, you can pass it via:
    --jwt <token>
  (sent as: Authorization: Bearer <token>)

Notes:
- PostgREST supports filtering/sorting/pagination through query parameters and HTTP Range.
- This CLI uses Range for safety and to work with db-max-rows.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

DEFAULT_BASE = os.environ.get("TIGERFETCH_BASE", "https://tigerblue-postgrest.fly.dev")


# -----------------------------
# HTTP + PostgREST helpers
# -----------------------------

@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


class PostgrestClient:
    def __init__(self, base_url: str, jwt: Optional[str] = None, timeout_s: int = 30):
        self.base_url = base_url.rstrip("/")
        self.jwt = jwt
        self.timeout_s = timeout_s

    def _request(
        self,
        method: str,
        path: str,
        query: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body_json: Optional[Dict[str, Any]] = None,
        range_header: Optional[str] = None,
        accept: str = "application/json",
    ) -> HttpResponse:
        q = ""
        if query:
            q = "?" + urllib.parse.urlencode(query, doseq=False, safe=",().*:\\")

        url = f"{self.base_url}/{path.lstrip('/')}" + q

        req_headers: Dict[str, str] = {
            "Accept": accept,
        }
        if self.jwt:
            req_headers["Authorization"] = f"Bearer {self.jwt}"
        if range_header:
            req_headers["Range"] = range_header
        if headers:
            req_headers.update(headers)

        data = None
        if body_json is not None:
            raw = json.dumps(body_json).encode("utf-8")
            data = raw
            req_headers.setdefault("Content-Type", "application/json")

        req = urllib.request.Request(url=url, method=method, headers=req_headers, data=data)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = resp.read()
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return HttpResponse(status=resp.status, headers=hdrs, body=body)
        except urllib.error.HTTPError as e:
            body = e.read() if hasattr(e, "read") else b""
            hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            return HttpResponse(status=e.code, headers=hdrs, body=body)

    def get(
        self,
        relation: str,
        *,
        query: Optional[Dict[str, str]] = None,
        range_from: int = 0,
        range_to: int = 49,
        prefer_count: Optional[str] = None,
    ) -> HttpResponse:
        headers = {}
        if prefer_count:
            headers["Prefer"] = f"count={prefer_count}"
        return self._request(
            "GET",
            relation,
            query=query,
            headers=headers,
            range_header=f"{range_from}-{range_to}",
        )

    def rpc(self, fn: str, payload: Dict[str, Any]) -> HttpResponse:
        return self._request("POST", f"rpc/{fn}", body_json=payload)


# -----------------------------
# Output formatting
# -----------------------------


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def as_iso(dt_obj: dt.datetime) -> str:
    # PostgREST is generally fine with RFC3339-ish strings.
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=dt.timezone.utc)
    return dt_obj.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_since(s: str) -> str:
    """Parse a since value.

    Accepts:
      - RFC3339-ish (2025-12-19T10:00:00Z)
      - YYYY-MM-DD
      - relative shortcuts: 24h, 7d, 30d
    Returns: RFC3339 UTC string.
    """
    s = s.strip()
    m = re.fullmatch(r"(\d+)([hd])", s)
    now = dt.datetime.now(dt.timezone.utc)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit == "h":
            return as_iso(now - dt.timedelta(hours=n))
        return as_iso(now - dt.timedelta(days=n))

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}$", s):
        d = dt.datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
        return as_iso(d)

    # assume already RFC3339-ish
    if s.endswith("Z"):
        return s
    return s


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=False))


def tabulate(rows: List[Dict[str, Any]], columns: Sequence[str]) -> str:
    if not rows:
        return "(no results)"

    # normalize values to strings
    str_rows: List[List[str]] = []
    for r in rows:
        str_rows.append(["" if r.get(c) is None else str(r.get(c)) for c in columns])

    widths = [len(c) for c in columns]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(vals: Sequence[str]) -> str:
        return " | ".join(vals[i].ljust(widths[i]) for i in range(len(columns)))

    header = fmt_row(columns)
    sep = "-+-".join("-" * w for w in widths)
    body = "\n".join(fmt_row(r) for r in str_rows)
    return f"{header}\n{sep}\n{body}"


def maybe_write_csv(path: str, rows: List[Dict[str, Any]], columns: Sequence[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(columns))
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in columns})


# -----------------------------
# Subcommands
# -----------------------------


def cmd_triage(args: argparse.Namespace) -> int:
    client = PostgrestClient(args.base_url, jwt=args.jwt, timeout_s=args.timeout)

    query: Dict[str, str] = {
        "order": f"{args.order}.{args.order_dir}",
    }

    # Projection
    if args.select:
        query["select"] = args.select

    # Severity filters
    if args.severity:
        if len(args.severity) == 1:
            query["severity_level"] = f"eq.{args.severity[0]}"
        else:
            query["severity_level"] = "in.(%s)" % (",".join(args.severity))

    # Source
    if args.source:
        query["source_name"] = f"eq.{args.source}"

    # Since
    if args.since:
        query["analysed_at"] = f"gte.{parse_since(args.since)}"

    # Keyword
    if args.keyword:
        # choose a safe-ish place to search: title
        query["title"] = f"ilike.*{args.keyword}*"

    resp = client.get("analysis_entries_lite", query=query, range_from=args.offset, range_to=args.offset + args.limit - 1)

    if resp.status >= 400:
        eprint(f"ERROR {resp.status}: {resp.body.decode('utf-8', errors='replace')}")
        return 2

    data = resp.json()

    if args.format == "json":
        print_json(data)
        return 0

    cols = args.columns or [
        "analysis_guid",
        "title",
        "severity_level",
        "confidence_pct",
        "cve_count",
        "ioc_count",
        "analysed_at",
        "source_name",
    ]
    print(tabulate(data, cols))
    return 0


def cmd_cve(args: argparse.Namespace) -> int:
    client = PostgrestClient(args.base_url, jwt=args.jwt, timeout_s=args.timeout)

    if args.subaction == "get":
        query = {
            "cve_id": f"eq.{args.cve_id}",
        }
        if args.select:
            query["select"] = args.select

        resp = client.get("cve_detail", query=query, range_from=0, range_to=0)
        if resp.status >= 400:
            eprint(f"ERROR {resp.status}: {resp.body.decode('utf-8', errors='replace')}")
            return 2

        data = resp.json()
        if args.format == "json":
            print_json(data[0] if data else {})
            return 0

        row = data[0] if data else {}
        cols = args.columns or [
            "cve_id",
            "cvss_base",
            "epss",
            "epss_percentile",
            "in_kev",
            "due_date",
            "mention_count",
            "last_seen",
            "description_en",
        ]
        print(tabulate([row], cols))
        return 0

    if args.subaction == "patchlist":
        # Prioritized list by (in_kev desc, epss desc, cvss desc)
        query: Dict[str, str] = {
            "order": "epss.desc,cvss_base.desc",
            "select": args.select
            or "cve_id,epss,cvss_base,in_kev,due_date,required_action,mention_count,last_seen,description_en",
        }

        if args.in_kev:
            query["in_kev"] = "is.true"
        if args.epss_gte is not None:
            query["epss"] = f"gte.{args.epss_gte}"
        if args.cvss_gte is not None:
            query["cvss_base"] = f"gte.{args.cvss_gte}"
        if args.mentioned_since:
            query["last_seen"] = f"gte.{parse_since(args.mentioned_since)}"

        resp = client.get("cve_detail", query=query, range_from=args.offset, range_to=args.offset + args.limit - 1)
        if resp.status >= 400:
            eprint(f"ERROR {resp.status}: {resp.body.decode('utf-8', errors='replace')}")
            return 2

        data = resp.json()

        if args.format == "json":
            print_json(data)
            return 0

        cols = args.columns or [
            "cve_id",
            "in_kev",
            "epss",
            "cvss_base",
            "due_date",
            "mention_count",
            "last_seen",
        ]
        print(tabulate(data, cols))
        return 0

    eprint("Unknown cve subaction")
    return 2


def cmd_campaign(args: argparse.Namespace) -> int:
    client = PostgrestClient(args.base_url, jwt=args.jwt, timeout_s=args.timeout)

    if args.subaction == "latest":
        query: Dict[str, str] = {
            "order": "last_seen.desc",
        }
        if args.kind:
            query["campaign_kind"] = f"eq.{args.kind}"
        if args.select:
            query["select"] = args.select

        resp = client.get("campaign_latest_seen", query=query, range_from=args.offset, range_to=args.offset + args.limit - 1)
        if resp.status >= 400:
            eprint(f"ERROR {resp.status}: {resp.body.decode('utf-8', errors='replace')}")
            return 2

        data = resp.json()
        if args.format == "json":
            print_json(data)
            return 0

        cols = args.columns or [
            "campaign_key",
            "campaign_kind",
            "last_seen",
            "cve_count",
            "item_mentions",
            "max_epss",
            "max_cvss_base",
        ]
        print(tabulate(data, cols))
        return 0

    if args.subaction == "rollup":
        query: Dict[str, str] = {
            "campaign_key": f"eq.{args.campaign_key}",
            "order": "mention_count.desc",
        }
        if args.select:
            query["select"] = args.select

        resp = client.get("campaign_cve_rollups", query=query, range_from=args.offset, range_to=args.offset + args.limit - 1)
        if resp.status >= 400:
            eprint(f"ERROR {resp.status}: {resp.body.decode('utf-8', errors='replace')}")
            return 2

        data = resp.json()
        if args.format == "json":
            print_json(data)
            return 0

        cols = args.columns or [
            "cve_id",
            "mention_count",
            "item_count",
            "source_count",
            "epss",
            "cvss_base",
            "first_seen",
            "last_seen",
            "description_en",
        ]
        print(tabulate(data, cols))
        return 0

    eprint("Unknown campaign subaction")
    return 2


def _extract_iocs_from_row(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Attempt to normalize IOC objects from `key_iocs`.

    We don't fully control the schema of key_iocs (JSON array), so we do best-effort:
    - if element is a dict, try to pick common fields: type/value/indicator/confidence/context
    - else treat as string value.
    """
    out: List[Dict[str, Any]] = []
    key_iocs = row.get("key_iocs")
    if not key_iocs:
        return out

    # key_iocs may already be a list/dict depending on JSON decoding
    if isinstance(key_iocs, str):
        # sometimes PostgREST returns json as decoded; but guard anyway
        try:
            key_iocs = json.loads(key_iocs)
        except Exception:
            key_iocs = [key_iocs]

    if isinstance(key_iocs, dict):
        key_iocs = [key_iocs]

    if not isinstance(key_iocs, list):
        return out

    for item in key_iocs:
        if isinstance(item, dict):
            out.append(
                {
                    "analysis_guid": row.get("analysis_guid"),
                    "title": row.get("title"),
                    "analysed_at": row.get("analysed_at"),
                    "source_name": row.get("source_name"),
                    "ioc_type": item.get("type") or item.get("ioc_type") or item.get("indicator_type"),
                    "ioc_value": item.get("value") or item.get("indicator") or item.get("ioc") or item.get("observable"),
                    "confidence": item.get("confidence"),
                    "context": item.get("context") or item.get("note") or item.get("description"),
                }
            )
        else:
            out.append(
                {
                    "analysis_guid": row.get("analysis_guid"),
                    "title": row.get("title"),
                    "analysed_at": row.get("analysed_at"),
                    "source_name": row.get("source_name"),
                    "ioc_type": None,
                    "ioc_value": str(item),
                    "confidence": None,
                    "context": None,
                }
            )

    return out


def cmd_ioc(args: argparse.Namespace) -> int:
    client = PostgrestClient(args.base_url, jwt=args.jwt, timeout_s=args.timeout)

    # Pull from analysis_entries_lite (includes key_iocs and avoids content)
    query: Dict[str, str] = {
        "order": "analysed_at.desc",
        "select": "analysis_guid,title,analysed_at,source_name,key_iocs",
    }

    if args.since:
        query["analysed_at"] = f"gte.{parse_since(args.since)}"

    if args.severity:
        if len(args.severity) == 1:
            query["severity_level"] = f"eq.{args.severity[0]}"
        else:
            query["severity_level"] = "in.(%s)" % (",".join(args.severity))

    resp = client.get("analysis_entries_lite", query=query, range_from=args.offset, range_to=args.offset + args.limit - 1)
    if resp.status >= 400:
        eprint(f"ERROR {resp.status}: {resp.body.decode('utf-8', errors='replace')}")
        return 2

    rows = resp.json()

    iocs: List[Dict[str, Any]] = []
    for r in rows:
        iocs.extend(_extract_iocs_from_row(r))

    # optional filter
    if args.contains:
        needle = args.contains.lower()
        iocs = [i for i in iocs if (i.get("ioc_value") or "").lower().find(needle) >= 0]

    if args.format == "json":
        print_json(iocs)
    else:
        cols = args.columns or [
            "ioc_type",
            "ioc_value",
            "confidence",
            "source_name",
            "analysed_at",
            "analysis_guid",
        ]
        print(tabulate(iocs, cols))

    if args.out_csv:
        cols = [
            "ioc_type",
            "ioc_value",
            "confidence",
            "context",
            "source_name",
            "analysed_at",
            "analysis_guid",
            "title",
        ]
        maybe_write_csv(args.out_csv, iocs, cols)
        eprint(f"Wrote CSV: {args.out_csv}")

    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(iocs, f, indent=2)
        eprint(f"Wrote JSON: {args.out_json}")

    return 0


# -----------------------------
# CLI wiring
# -----------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tigerfetch",
        description="Tigerfetch PostgREST analysis utility (triage / cve / campaign / ioc)",
    )

    p.add_argument("--base-url", default=DEFAULT_BASE, help=f"PostgREST base URL (default: {DEFAULT_BASE} or env TIGERFETCH_BASE)")
    p.add_argument("--jwt", default=os.environ.get("TIGERFETCH_JWT"), help="JWT token to send as Authorization: Bearer <token> (or env TIGERFETCH_JWT)")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")

    sub = p.add_subparsers(dest="command", required=True)

    # triage
    tri = sub.add_parser("triage", help="List recent analysis entries (lite) with filters")
    tri.add_argument("--severity", nargs="*", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Severity levels to include")
    tri.add_argument("--since", help="Only include analysed_at >= since (YYYY-MM-DD | RFC3339 | 24h | 7d | 30d)")
    tri.add_argument("--source", help="Filter by source_name (exact)")
    tri.add_argument("--keyword", help="Keyword search in title (ilike)")
    tri.add_argument("--order", default="analysed_at", help="Order column (default: analysed_at)")
    tri.add_argument("--order-dir", default="desc", choices=["asc", "desc"], help="Order direction")
    tri.add_argument("--select", help="PostgREST select projection")
    tri.add_argument("--offset", type=int, default=0, help="Pagination offset (Range start)")
    tri.add_argument("--limit", type=int, default=50, help="Pagination limit")
    tri.add_argument("--format", choices=["table", "json"], default="table")
    tri.add_argument("--columns", nargs="*", help="Table columns (table format only)")
    tri.set_defaults(func=cmd_triage)

    # cve
    cve = sub.add_parser("cve", help="CVE operations")
    cve_sub = cve.add_subparsers(dest="subaction", required=True)

    cve_get = cve_sub.add_parser("get", help="Fetch consolidated CVE detail")
    cve_get.add_argument("cve_id", help="CVE ID (e.g. CVE-2024-12345)")
    cve_get.add_argument("--select", help="PostgREST select projection")
    cve_get.add_argument("--format", choices=["table", "json"], default="table")
    cve_get.add_argument("--columns", nargs="*", help="Table columns")
    cve_get.set_defaults(func=cmd_cve)

    cve_patch = cve_sub.add_parser("patchlist", help="Generate a prioritized patch list from cve_detail")
    cve_patch.add_argument("--in-kev", action="store_true", help="Only include CVEs in KEV")
    cve_patch.add_argument("--epss-gte", type=float, help="Only include epss >= value")
    cve_patch.add_argument("--cvss-gte", type=float, help="Only include cvss_base >= value")
    cve_patch.add_argument("--mentioned-since", help="Only include CVEs last_seen >= since (YYYY-MM-DD | RFC3339 | 24h | 7d | 30d)")
    cve_patch.add_argument("--select", help="PostgREST select projection")
    cve_patch.add_argument("--offset", type=int, default=0)
    cve_patch.add_argument("--limit", type=int, default=50)
    cve_patch.add_argument("--format", choices=["table", "json"], default="table")
    cve_patch.add_argument("--columns", nargs="*", help="Table columns")
    cve_patch.set_defaults(func=cmd_cve)

    # campaign
    camp = sub.add_parser("campaign", help="Campaign exploration")
    camp_sub = camp.add_subparsers(dest="subaction", required=True)

    camp_latest = camp_sub.add_parser("latest", help="List latest-seen campaigns")
    camp_latest.add_argument("--kind", choices=["patch_wave", "active_exploitation", "cve_story"], help="Filter by campaign_kind")
    camp_latest.add_argument("--select", help="PostgREST select projection")
    camp_latest.add_argument("--offset", type=int, default=0)
    camp_latest.add_argument("--limit", type=int, default=50)
    camp_latest.add_argument("--format", choices=["table", "json"], default="table")
    camp_latest.add_argument("--columns", nargs="*", help="Table columns")
    camp_latest.set_defaults(func=cmd_campaign)

    camp_roll = camp_sub.add_parser("rollup", help="Show CVE rollups for a campaign_key")
    camp_roll.add_argument("campaign_key", help="Campaign key")
    camp_roll.add_argument("--select", help="PostgREST select projection")
    camp_roll.add_argument("--offset", type=int, default=0)
    camp_roll.add_argument("--limit", type=int, default=100)
    camp_roll.add_argument("--format", choices=["table", "json"], default="table")
    camp_roll.add_argument("--columns", nargs="*", help="Table columns")
    camp_roll.set_defaults(func=cmd_campaign)

    # ioc
    ioc = sub.add_parser("ioc", help="Extract IOCs from recent analyses")
    ioc.add_argument("--since", help="Only include analysed_at >= since (YYYY-MM-DD | RFC3339 | 24h | 7d | 30d)")
    ioc.add_argument("--severity", nargs="*", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Severity levels to include")
    ioc.add_argument("--contains", help="Filter IOC values containing substring")
    ioc.add_argument("--offset", type=int, default=0)
    ioc.add_argument("--limit", type=int, default=50, help="How many analyses to scan for IOCs")
    ioc.add_argument("--format", choices=["table", "json"], default="table")
    ioc.add_argument("--columns", nargs="*", help="Table columns (table format only)")
    ioc.add_argument("--out-csv", help="Write extracted IOCs to CSV")
    ioc.add_argument("--out-json", help="Write extracted IOCs to JSON")
    ioc.set_defaults(func=cmd_ioc)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        eprint("Interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
