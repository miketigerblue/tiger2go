# Threat-intel data sources — tiered ingest plan

Beyond the current set of feeds (NVD, EPSS, CISA KEV, RSS / Atom news), there
are three coherent tiers of additional sources that fill specific blind spots.
This doc records the plan; PRs reference back here so the rationale stays
linked to the implementation.

The tiers are ordered by perceived **value per unit of effort**, not by
sophistication. Tier 1 is the biggest gap; Tier 3 is the cleanest upgrade.

---

## Tier 1 — Supply-chain + exploit-commodity signal

These directly address blind spots in the current feeds: package-level
advisories that NVD systematically misses, IOC validation we currently can't
do, and exploit-commodity timing that runs weeks ahead of EPSS movement.

| Dataset | Source / format | What it adds | Effort | Status |
|---|---|---|---|---|
| **OSV** | `osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip` — JSON bundles per ecosystem | Per-ecosystem CVE / advisory feed for npm, PyPI, Maven, Go, RubyGems, crates.io, Packagist, NuGet, Pub, Hex, Hackage. NVD systematically misses package-level supply-chain advisories. With tiger-watch's SBOM matching, this is the join key. | 1–2 d | **Shipped — [PR #19](https://github.com/miketigerblue/tiger2go/pull/19) (OSV runner + `osv_vulns` table)** |
| **GitHub Advisory DB (GHSA)** | `api.github.com/advisories` — REST + GraphQL | Slightly higher fidelity than OSV's GitHub feed, with full CVSS + CWE per advisory. Co-references OSV. Requires a GitHub token (free PAT works). | 1 d | planned |
| **abuse.ch — ThreatFox / MalwareBazaar / URLhaus** | bulk CSV + JSON + MISP feed | IOC database keyed by malware family. Lets us *validate* `analysis.key_iocs` — does the LLM-extracted IPv4 actually appear in a known ThreatFox C2 listing? Joins straight to `analysis_malware` via the family name. Free, no auth. | 1–2 d | planned |
| **Nuclei templates** | `github.com/projectdiscovery/nuclei-templates` (git poll or release feed) | When a CVE gets a Nuclei template, it has just become *commodity* — every scanner now finds it. Tracking template additions is a leading indicator that runs 2–6 weeks ahead of EPSS movement. | 1 d | planned |
| **Metasploit module metadata** | `github.com/rapid7/metasploit-framework` (git poll) | Same logic — when a CVE gets a Metasploit module, exploit-availability has crossed a threshold. | ~1 d | planned |

**Why this tier first:** these are the inputs that *directly increase the
quality of fields we already have*. OSV makes tiger-watch SBOM matching
useful; abuse.ch turns LLM-extracted IOCs from claims into facts; Nuclei +
Metasploit give us early-warning signals EPSS can't.

---

## Tier 2 — Network telemetry

Turns "exploitable" into "being attacked".

| Dataset | Source / format | What it adds | Effort |
|---|---|---|---|
| **GreyNoise community** | `api.greynoise.io` — free tier ~10K queries/day | Tells you whether an IP is internet-noise (scanning everyone) or targeted (scanning *you*). When joined against `analysis.key_iocs[type=ipv4]`, instantly answers "is this a real adversary or commodity scanning?" | 1–2 d |
| **DShield top sources** (SANS) | `isc.sans.edu` — JSON | Top 1000 attacking IPs daily, plus port-scan trends. Free, low volume. Powers a "is this CVE seeing scanning waves right now?" view. | half day |
| **Censys / Shodan** | `api.censys.io`, `api.shodan.io` — paid | Internet-exposed asset counts per product/version. With `cve_kev` joined to Censys exposure counts, you can quantify "this CVE affects 487K exposed F5 BIG-IP devices globally" — useful for CISO briefs. | 1–2 d |
| **CIRCL Passive DNS** | `circl.lu` — auth required, free for research | Historical DNS resolution for IOC pivoting. When an analysis surfaces a malicious domain, this lets you see what other domains shared its IP. | 2–3 d |

**Why this tier matters for T2:** convergence detection currently combines
news sources. Adding network telemetry distinguishes "rising story" from
"rising activity" — those are different signals and CISO briefs benefit
from both being visible.

---

## Tier 3 — Structured vendor advisories (replace news with primary source)

Currently we pick up most vendor advisories via news (BleepingComputer,
SecurityWeek, etc.). Going direct gives cleaner structured data 6–48 h
ahead of press.

| Vendor | Source | Format | Why |
|---|---|---|---|
| **Microsoft MSRC** | `api.msrc.microsoft.com` | CVRF / CSAF JSON | Patch Tuesday in structured form, with full product/version trees |
| **Red Hat** | `access.redhat.com/security/data/csaf/v2/` | CSAF JSON | All RHEL advisories, mapped to CVE + CWE + CPE |
| **Cisco PSIRT OpenVuln** | `api.cisco.com/security/advisories` | REST | The Cisco gap is real — they have ~89 KEV CVEs but our news picks up only the high-profile ones |
| **Palo Alto** | `security.paloaltonetworks.com` | RSS + JSON | RSS already in our feeds; JSON adds CPE + Cortex severity |
| **Oracle CPU** | `oracle.com/security-alerts` | HTML + CSV | Quarterly — covers WebLogic / Java / MySQL, none well-covered in our news |
| **VMware (Broadcom)** | broadcom.com | RSS | Now under Broadcom; format needs confirming post-acquisition |
| **SAP Security Notes** | `sap.com` | XML (paywall — legitimate access needed) | High-value if SAP is in scope; pricey otherwise |

**The pattern:** vendor advisories arrive *before* news writes about them.
Ingesting them directly gives T2 an earlier signal than the news pipeline
can.

---

## Cross-cutting design notes

1. **One package per source under `internal/<name>/`**, following the OSV
   pattern shipped in PR #19: a `Runner` struct with `Run(ctx)`, a config
   in `internal/config/`, Prometheus metrics in `internal/metrics/`, a
   migration with denormalised columns for hot queries + a `raw` jsonb
   column for round-trip preservation, and unit tests for the parsing
   helpers.
2. **Idempotent upserts** — `WHERE modified IS DISTINCT FROM EXCLUDED.modified`
   (or analogous) so re-fetching a bundle with no upstream changes touches
   zero rows. Keeps the audit trail clean.
3. **Disabled by default** — each ingestor is gated by `Enabled` in its
   config block. CI runs migrations but doesn't fire fetches.
4. **No secret in the repo** — credentials (GitHub PAT for GHSA, Censys/
   Shodan API keys, CIRCL auth) come from env-var overrides via viper.
5. **Join keys we keep top-of-mind**:
   - `cve_id` joins all CVE-style sources (NVD, EPSS, KEV, GHSA, OSV
     aliases, Nuclei, Metasploit).
   - `package_name + ecosystem` joins OSV / GHSA to tiger-watch's SBOM
     consumer.
   - `malware_family` joins abuse.ch to `analysis_malware`.
   - `ipv4` / `domain` joins GreyNoise / Passive DNS to
     `analysis.key_iocs`.

---

## Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-16 | Add Tier 1 sources first, one PR per source. | Bigger blind-spot gap than network telemetry or vendor advisories; OSV unlocks SBOM matching which is the most analyst-visible win. |
| 2026-05-16 | OSV shipped first within Tier 1. | No auth, simple JSON bundle format, foundational for downstream SBOM join. Establishes the runner pattern the other sources follow. |
| 2026-05-16 | Don't compute CVSS scores from vectors in v1 of OSV. | 4,971 of 19,563 PyPI advisories ship only the CVSS_V3 vector. Storing the vector in `severity` jsonb is enough until someone needs `WHERE cvss_v3 >= 7`. Adding a vector evaluator is a follow-up. |
