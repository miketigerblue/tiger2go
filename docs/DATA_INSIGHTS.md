<p align="center">
  <img src="../tigerfetch_hunt_the_signal.png" alt="TigerFetch" width="200" />
</p>

# TigerFetch Data Insights

> Two snapshots below. The **current** snapshot (2026-05-17) is the
> live lake after the Tier-1 ingestors landed and the May-2026 legacy
> migration completed. The **2026-04-12 baseline** is preserved below
> for trend comparison.

---

## Snapshot — 2026-05-17 (v1.4.0)

> **Source:** Local dev container (`localhost:5432/tiger2go`). All numbers below come from a single point-in-time query; reproducible via `mcp__pg-introspect-tiger2go__run_query` or `psql` against the same DSN.

### 0.1 Lake at a glance

| Domain | Volume | Notes |
|---|---|---|
| `cve_enriched` (NVD) | 351,175 CVEs | 95.0 % have EPSS populated post-materialisation |
| `cve_kev` (active) | 1,590 | First-class table since `[1.3.0]` |
| `epss_daily` | ~11M rows across 3 monthly partitions | 326k CVEs/day, ~217 new CVEs/day inbound |
| `ghsa_advisories` | 333,301 | 329,645 carry a `cve_id` link |
| `osv_vulns` | 264,026 | PyPI alone: 19,564 |
| `nuclei_templates` | 5,558 | 1,610 critical-severity |
| `msf_modules` | 6,632 | 1,664 excellent/great-rank (weaponised) |
| `urlhaus_urls` | 25,784 | 2,155 currently online |
| `threatfox_iocs` | 3,488 | 7-day rolling window |
| `malwarebazaar_samples` | 319 | 60-min rolling window |
| `analysis` (tiger-eye) | 2,595 | 290 enriched in last 7 days |
| `sbom_packages` (tiger-watch) | 478 | across 18 watchlisted services |

### 0.2 The risk pyramid (current)

EPSS distribution across the 351,177 CVEs in `cve_enriched`:

```
           /\           8,054 CVEs  ( 2.3%)   Critical  >= 50% exploitation probability
          /  \
         /    \        15,854 CVEs  ( 4.5%)   High      10 - 50%
        /      \
       /        \      53,083 CVEs  (15.1%)   Medium     1 - 10%
      /          \
     /            \   165,909 CVEs  (47.2%)   Low        0.1 - 1%
    /              \
   /________________\ 108,277 CVEs  (30.8%)   Negligible < 0.1%
```

Compared to the April baseline: the critical band has grown from 7,123 → 8,054 (+13.1 %) and overall CVE count from 326k → 351k (+7.7 %). The 2.3 % "critical" share is roughly stable.

### 0.3 Apex predators

CVEs with **EPSS ≥ 90 % AND CVSS ≥ 9.0** — both the model and the static score agree these are severe and actively exploited: **719 entries** as of this snapshot. These are the patching priority-1 list.

### 0.4 What the new sources reveal

The Tier-1 ingestors let analysts answer questions tigerfetch couldn't before:

- **"Is there a Metasploit module?"** — 1,664 weaponised modules (excellent + great rank); join via `msf_modules.cves[]`.
- **"Is there a Nuclei template?"** — 5,558 templates covering 4,103 distinct CVEs; signals the "scanner commodity" threshold has been crossed.
- **"Does our SBOM contain any of this?"** — `sbom_packages × osv_vulns × ghsa_advisories` with proper version-range evaluation in tiger-watch.
- **"What's hot right now?"** — `threatfox_iocs.first_seen > now() - '24 hours'` grouped by `malware_printable` produces the ClearFake/Cobalt Strike/VShell live-campaign ranking that powers the o2 voice agent.

---

## Snapshot — 2026-04-12 (historical baseline, v1.2.0)

### 1. Dataset at a Glance

| Domain | Volume | Coverage |
|--------|--------|----------|
| EPSS daily scores | ~10.3M rows | 326k CVEs/day, 35 days of data |
| NVD enriched CVEs | 337k unique CVEs | Full CVSS + CWE + description metadata |
| Feed articles | 10,384 articles | 26 feeds across 8 countries |
| CISA KEV | Tracked via cursor | Known-exploited subset of NVD |

### Pipeline Status (as of snapshot)

| Pipeline | First Ingestion | Latest Cursor | Coverage |
|----------|-----------------|---------------|----------|
| Feed articles | 2025-09-13 | 2026-04-11 | Continuous |
| EPSS daily | 2026-03-04 | 2026-04-11 | 32 of 39 days |
| NVD | 2026-03-04 | 2026-04-12 | Continuous |
| CISA KEV | 2026-03-04 | 2026-04-08 | Continuous |

The database was first populated on **March 4, 2026**. The archive table contains articles backdated to September 2025 because RSS feeds serve historical items, but live ingestion has been running for 39 days.

EPSS gaps: April partition has data for 4 of 11 days (Apr 1, 2, 4, 11). Missing days (Apr 3, 5-10) are due to container downtime during code review fixes and a pagination bug that produced partial ingestions (since cleaned up). These will backfill automatically on the next EPSS cycle.

---

## 2. The Risk Pyramid

EPSS risk distribution as of April 11, 2026 (326,508 CVEs scored):

```
           /\           7,123 CVEs  ( 2.2%)   Critical  >= 50% exploitation probability
          /  \
         /    \        15,560 CVEs  ( 4.8%)   High      10 - 50%
        /      \
       /        \      52,408 CVEs  (16.1%)   Medium     1 - 10%
      /          \
     /            \   160,993 CVEs  (49.3%)   Low        0.1 - 1%
    /              \
   /________________\  90,424 CVEs  (27.7%)   Negligible < 0.1%
```

**Only 2.2% of all CVEs have a >= 50% chance of being exploited.** Those 7,123 vulnerabilities are where defenders should focus. The remaining 97.8% are noise at any given point in time — though individual CVEs can move between bands rapidly (see below).

---

## 3. Sleeper CVEs — From Noise Floor to Critical

The most operationally significant finding in the dataset: CVEs that went from **< 1% EPSS to > 50%** in 38 days. The EPSS model detected a change in real-world exploitability that static CVSS scores could never signal.

| CVE | EPSS Mar 4 | EPSS Apr 11 | Change | Description |
|-----|-----------|-------------|--------|-------------|
| CVE-2025-71243 | 0.11% | **83.68%** | +75,284% | SPIP plugin Remote Code Execution |
| CVE-2025-50286 | 0.90% | **58.40%** | +6,425% | Grav CMS malicious plugin upload RCE |
| CVE-2024-28752 | 0.59% | **55.15%** | +9,248% | Apache CXF SSRF |
| CVE-2023-34092 | 0.46% | **55.11%** | +11,854% | Vite dev server path traversal |
| CVE-2025-69516 | 0.11% | **53.16%** | +49,580% | Tactical RMM Jinja2 SSTI |

CVE-2025-71243 increased **75,000%** — from background noise to the 97th percentile. These are the signals TigerFetch exists to surface.

---

## 4. Threat Velocity — Weekly Movement

In the 5-day window from April 6 to April 11:

| Metric | Count |
|--------|-------|
| CVEs surging (EPSS up > 50% relative, starting above 0.1%) | **677** |
| CVEs crossed 50% critical threshold | **18** |
| CVEs crossed 10% high threshold | **64** |
| CVEs falling fast (EPSS down > 50% relative) | 63 |

The threat surface is **expanding, not contracting** — surges outnumber declines 10:1.

### CVE Growth Rate

**8,243 new CVEs** entered the EPSS tracking universe between March 4 and April 11 — approximately **217 new CVEs per day**. The firehose does not slow down.

---

## 5. Most Exploitable Weakness Classes

Joining NVD CWE classifications with EPSS scores for CVEs above 10% exploitation probability:

| CWE | Weakness | CVEs | Avg EPSS | Avg CVSS |
|-----|----------|------|----------|----------|
| CWE-918 | **Server-Side Request Forgery** | 124 | 66.2% | 7.9 |
| CWE-287 | Improper Authentication | 130 | 64.7% | 8.8 |
| CWE-22 | Path Traversal | 475 | 57.2% | 8.0 |
| CWE-798 | Hard-coded Credentials | 49 | 55.2% | 9.2 |
| CWE-94 | Code Injection | 222 | 53.3% | 8.9 |
| CWE-89 | SQL Injection | 594 | 51.8% | 9.0 |
| CWE-502 | Deserialization of Untrusted Data | 257 | 51.0% | 9.0 |

**SSRF (CWE-918) has the highest average exploit probability** despite a relatively modest CVSS of 7.9. This is the "CVSS says High, reality says Critical" gap that longitudinal EPSS data reveals. SQL Injection has the most CVEs in the high-risk zone (594), but SSRF is exploited more consistently.

---

## 6. The Apex Predators — Highest Combined Risk

CVEs with **EPSS >= 50% AND CVSS >= 9.0** — both the model and the static score agree these are severe and actively exploited:

| CVE | EPSS | CVSS | Description |
|-----|------|------|-------------|
| CVE-2021-22986 | 94.5% | 9.8 | F5 BIG-IP iControl REST unauthenticated RCE |
| CVE-2022-46169 | 94.5% | 9.8 | Cacti command injection (unauthenticated) |
| CVE-2020-1938 | 94.5% | 9.8 | Apache Tomcat AJP Ghostcat |
| CVE-2021-22205 | 94.5% | 10.0 | GitLab CE/EE image parser RCE |
| CVE-2024-23897 | 94.5% | 9.8 | Jenkins arbitrary file read |
| CVE-2022-22947 | 94.5% | 10.0 | Spring Cloud Gateway code injection |
| CVE-2019-19781 | 94.4% | 9.8 | Citrix ADC directory traversal |
| CVE-2021-26084 | 94.4% | 9.8 | Confluence OGNL injection |
| CVE-2022-1388 | 94.5% | 9.8 | F5 BIG-IP iControl REST auth bypass |
| CVE-2020-14882 | 94.5% | 9.8 | Oracle WebLogic console takeover |

These are the "hall of fame" — well-known, heavily weaponised vulnerabilities that remain actively exploited years after disclosure. Any organisation exposing these products should treat them as **assumed-breached** if unpatched.

---

## 7. Feed Intake Cadence

Weekly article ingestion volume since September 2025:

| Period | Avg Articles/Week | Notes |
|--------|-------------------|-------|
| Sep - Oct 2025 | ~38 | Initial feed set, low volume |
| Nov 2025 | ~102 | Feed expansion |
| Dec 2025 | ~220 | CERT-Bund, Debian, MSRC added |
| Jan 2026 | ~270 | Steady state |
| Feb 2026 | ~430 | Spike: 2,088 articles week of Feb 16 |
| Mar - Apr 2026 | ~616 | Full 26-feed complement |

### Top Feeds by Volume

| Feed | Articles |
|------|----------|
| Microsoft MSRC | 3,482 |
| CERT-Bund (Germany) | 1,348 |
| Bleeping Computer | 879 |
| The Hacker News | 750 |
| Dark Reading | 541 |
| JPCERT (Japan) | 427 |
| CISA Advisories | 413 |
| Ubuntu Security | 402 |
| NCSC UK | 347 |
| SANS ISC | 277 |

Microsoft MSRC alone accounts for **33.5%** of all ingested articles, reflecting the breadth of the Windows/Azure/Office advisory surface.

---

## 8. Key Takeaways

1. **CVSS lies, EPSS doesn't.** Static severity scores miss what attackers actually target. SSRF averages 66% exploitation probability at CVSS 7.9 — while many CVSS 9.8 vulnerabilities sit below 1% EPSS.

2. **The sleeper pattern is the killer feature.** CVEs that jump from noise floor to critical in days are the signals that justify a longitudinal EPSS dataset. Point-in-time snapshots miss the trajectory.

3. **The 2.2% rule.** Only 7,123 of 326,508 scored CVEs have a >= 50% chance of exploitation. Prioritisation should start there, not with "all criticals."

4. **217 new CVEs per day.** The vulnerability universe grows by ~1,500/week. Without automated ingestion and scoring, manual triage is impossible at scale.

5. **Threat velocity is net-positive.** Surging CVEs outnumber declining ones 10:1 in any given week. The attack surface expands faster than it contracts.

---

*Generated from 39 days of TigerFetch ingestion data. Queries available in the repo for reproduction against any TigerFetch PostgreSQL instance.*
