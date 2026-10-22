<p align="center">
  <img src="../tigerfetch_hunt_the_signal.png" alt="TigerFetch" width="200" />
</p>

# TigerFetch Data Insights

> Historical snapshots from **17 May 2026** and **12 April 2026**.
> Interpretations corrected on **14 October 2026**. The original measurements
> have not been rerun for this editorial update; they are not current lake totals.

## How to read these snapshots

**EPSS** estimates the probability of exploitation activity for a CVE over the next 30 days. A high score is not proof that exploitation has occurred. A low score does not establish safety. [FIRST: EPSS](https://www.first.org/epss/)

**CVSS Base** describes technical severity. It does not, alone, establish risk to a particular environment. [FIRST: CVSS guidance](https://www.first.org/cvss/v4.0/user-guide)

Prioritisation also depends on whether an affected product and version are present, their exposure and business importance, available controls, and evidence of known exploitation. EPSS is one input to that decision. [FIRST: EPSS FAQ](https://www.first.org/epss/faq)

Counts below describe the retained dataset and the stated selection rules. Feed coverage, missing dates, model versions and changes in the scored population can affect comparisons. The historical snapshots do not establish overall attacker activity or compromise of any particular system.

---

## Snapshot — 2026-05-17 (v1.4.0)

**Recorded source:** the local TigerFetch database (then named Tiger2Go) after the Tier-1 ingestors and May migration. Historical values are preserved below; rerunning queries against a changed database will not necessarily reproduce this snapshot.

### Lake at a glance

| Domain | Volume | Notes |
|---|---|---|
| `cve_enriched` (NVD) | 351,175 CVEs | 95.0 % have EPSS populated post-materialisation |
| `cve_kev` (active) | 1,590 | First-class table since `[1.3.0]` |
| `epss_daily` | ~11M rows across 3 monthly partitions | 326k CVEs/day, ~217 new CVEs/day inbound |
| `ghsa_advisories` | 333,301 | 329,645 carry a `cve_id` link |
| `osv_vulns` | 264,026 | PyPI alone: 19,564 |
| `nuclei_templates` | 5,558 | 1,610 critical-severity |
| `msf_modules` | 6,632 | 1,664 modules with excellent/great rank |
| `urlhaus_urls` | 25,784 | 2,155 currently online |
| `threatfox_iocs` | 3,488 | 7-day rolling window |
| `malwarebazaar_samples` | 319 | 60-min rolling window |
| `analysis` (tiger-eye) | 2,595 | 290 enriched in last 7 days |
| `sbom_packages` (tiger-watch) | 478 | across 18 watchlisted services |

### EPSS distribution

The original distribution reports **351,177 CVEs**. Its bands are score ranges, not severity labels or recommended remediation deadlines.

| Reported EPSS score | CVEs | Share |
|---|---:|---:|
| ≥ 50% | 8,054 | 2.3% |
| 10% to < 50% | 15,854 | 4.5% |
| 1% to < 10% | 53,083 | 15.1% |
| 0.1% to < 1% | 165,909 | 47.2% |
| < 0.1% | 108,277 | 30.8% |

The volume table reports 351,175 NVD records while this distribution totals 351,177. That two-record discrepancy is retained explicitly rather than silently treating the populations as identical.

The ≥ 50% band increased from 7,123 in the April baseline to 8,054 in May, a 13.1% increase. The reported scored population also grew. This is a comparison of two dataset snapshots, not an estimate of growth in actual exploitation.

### High severity and high predicted likelihood

The snapshot reports **719 entries with EPSS ≥ 90% and CVSS ≥ 9.0**. This identifies a set for closer review. Neither the conjunction of these scores nor its size establishes active exploitation, affected assets in a specific estate, or a universal patching order.

### What the additional sources make queryable

- **Metasploit:** the snapshot records 1,664 modules with excellent/great rank. The `cves[]` mapping can connect modules to CVEs; module availability does not establish observed attacks.
- **Nuclei:** 5,558 templates cover 4,103 distinct CVEs in the recorded snapshot. A template is a detection or testing resource, not proof of exploitation.
- **Package exposure:** `sbom_packages`, OSV and GHSA can support affected-package matching when version ranges and package identity are evaluated.
- **IOC reporting:** ThreatFox records can be grouped by first-seen time and malware label. Those counts describe reports visible through that feed, not the size or prevalence of a campaign.

---

## Snapshot — 2026-04-12 (historical baseline, v1.2.0)

### Dataset at a glance

| Domain | Volume | Coverage |
|--------|--------|----------|
| EPSS daily scores | ~10.3M rows | 326k CVEs/day, 35 days of data |
| NVD enriched CVEs | 337k unique CVEs | Full CVSS + CWE + description metadata |
| Feed articles | 10,384 articles | 26 feeds across 8 countries |
| CISA KEV | Tracked via cursor | Known-exploited subset of NVD |

The original notes say this database was first populated on **4 March 2026**, while its retained article dates reach back to September 2025. Historical article dates therefore cannot establish how long this database was ingesting or continuously available.

The notes report EPSS coverage for **32 of 39 days**, including only 4 of the first 11 April dates at that snapshot. They attribute gaps to downtime and a pagination defect, with backfill planned. This record does not verify when each gap was subsequently filled.

### EPSS distribution

Reported scores as of **11 April 2026**, across **326,508 CVEs**:

| Reported EPSS score | CVEs | Share |
|---|---:|---:|
| ≥ 50% | 7,123 | 2.2% |
| 10% to < 50% | 15,560 | 4.8% |
| 1% to < 10% | 52,408 | 16.1% |
| 0.1% to < 1% | 160,993 | 49.3% |
| < 0.1% | 90,424 | 27.7% |

The 2.2% figure is the share of this scored population above a chosen threshold. It is not an observed exploitation rate, and the remainder should not be dismissed as noise. Asset relevance and other evidence can justify action below that threshold.

### Historical score movements

The following reported scores moved from below 1% to above 50% between 4 March and 11 April. Changes are shown in **percentage points**, calculated from the displayed rounded scores.

| CVE | EPSS 4 Mar | EPSS 11 Apr | Change (percentage points) | Recorded description |
|---|---:|---:|---:|---|
| CVE-2025-71243 | 0.11% | 83.68% | +83.57 | SPIP plugin Remote Code Execution |
| CVE-2025-50286 | 0.90% | 58.40% | +57.50 | Grav CMS malicious plugin upload RCE |
| CVE-2024-28752 | 0.59% | 55.15% | +54.56 | Apache CXF SSRF |
| CVE-2023-34092 | 0.46% | 55.11% | +54.65 | Vite dev server path traversal |
| CVE-2025-69516 | 0.11% | 53.16% | +53.05 | Tactical RMM Jinja2 SSTI |

These are changes in model estimates, not observed attack counts. The table does not identify the cause of each movement, verify the descriptions against current vendor advisories, or provide percentile values. Longitudinal storage makes those changes inspectable; determining their significance requires additional evidence.

### Movement over 6–11 April

| Metric | Count |
|--------|-------|
| CVEs with rising scores (EPSS up > 50% relative, starting above 0.1%) | **677** |
| CVEs crossed 50% EPSS threshold | **18** |
| CVEs crossed 10% EPSS threshold | **64** |
| CVEs with falling scores (EPSS down > 50% relative) | 63 |

The recorded counts show more rising than falling scores under these selection rules in this five-day window. They do not establish that the attack surface expanded, that exploitation increased by the same ratio, or that the pattern holds in other weeks.

The snapshot also reports **8,243 additional CVEs in the scored population** between 4 March and 11 April: about **217 per day** over the 38-day interval. Additions to that population need not all be newly disclosed vulnerabilities.

### Weakness classes in the selected higher-score cohort

The original query joined NVD CWE classifications with CVEs whose EPSS exceeded 10%.

| CWE | Weakness | CVEs | Avg EPSS | Avg CVSS |
|-----|----------|------|----------|----------|
| CWE-918 | **Server-Side Request Forgery** | 124 | 66.2% | 7.9 |
| CWE-287 | Improper Authentication | 130 | 64.7% | 8.8 |
| CWE-22 | Path Traversal | 475 | 57.2% | 8.0 |
| CWE-798 | Hard-coded Credentials | 49 | 55.2% | 9.2 |
| CWE-94 | Code Injection | 222 | 53.3% | 8.9 |
| CWE-89 | SQL Injection | 594 | 51.8% | 9.0 |
| CWE-502 | Deserialization of Untrusted Data | 257 | 51.0% | 9.0 |

Within this selected cohort, SSRF has the highest reported mean EPSS. Conditioning on scores above 10% excludes lower-scoring CVEs in each class. These averages therefore do not rank exploitation frequency across all weaknesses or show that SSRF is exploited more consistently.

### Examples combining high CVSS and EPSS

The historical selection used **EPSS ≥ 50% and CVSS ≥ 9.0**:

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

These scores can support review of affected systems. The table does not contain dated exploitation evidence or host telemetry, so it cannot establish ongoing exploitation or compromise. Known-exploitation claims need their own source and date; response decisions also need actual asset and exposure context.

### Feed composition

The original top-feed counts were:

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

Microsoft MSRC accounts for approximately 33.5% of the 10,384 retained articles. That is a property of this corpus and its source selection, not Microsoft's share of the global threat landscape.

The earlier version also presented article dates from September 2025 as an ingestion-growth timeline. Because the same notes say this database started in March 2026 and received historical items, that timeline has been removed: publication history and ingestion history are different measurements.

## What these snapshots support

- A dated account of source coverage and the distribution of recorded scores.
- Investigation of score changes, with the scoring population and missing days made explicit.
- Joining vulnerability evidence to affected products, packages and exposure.
- Questions for deeper analysis, without converting model scores or feed counts into claims of confirmed attacks.

For the engineering work behind the May migration, see [Migrating a threat intelligence lake without losing its history](https://github.com/miketigerblue/miketigerblue/blob/main/evidence/2026-05-lake-migration.md).

*This revision corrects interpretation and presentation. It preserves reported historical measurements, flags unresolved population differences, and does not claim a fresh validation of the underlying snapshots.*
