package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NvdResponse struct {
	ResultsPerPage  int          `json:"resultsPerPage"`
	StartIndex      int          `json:"startIndex"`
	TotalResults    int          `json:"totalResults"`
	Format          string       `json:"format"`
	Version         string       `json:"version"`
	Timestamp       string       `json:"timestamp"`
	Vulnerabilities []NvdCveItem `json:"vulnerabilities"`
}

type NvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NvdCveItem struct {
	Cve struct {
		ID string `json:"id"`
		// Which CNA issued the record — the only way to tell a vendor
		// PSIRT's own assessment from cve@mitre.org's.
		SourceIdentifier string `json:"sourceIdentifier,omitempty"`
		// First publication, as distinct from last revision. Without
		// it the lake cannot answer "what is new this week" at all: a
		// 2015 CVE that NVD touched yesterday is indistinguishable
		// from one disclosed yesterday.
		Published    string `json:"published,omitempty"`
		LastModified string `json:"lastModified"`
		// Analysis state — Analyzed / Modified / Deferred / Rejected /
		// Awaiting Analysis. Rejected CVEs are withdrawn, and without
		// this the only way to spot one is to string-match the
		// description prose; 18,162 were sitting in the lake
		// indistinguishable from live findings. Deferred matters too:
		// NVD has abandoned those, so they never gain configurations
		// and can never match an SBOM — "not affected" and "never
		// analysed" were the same answer until now.
		VulnStatus string `json:"vulnStatus,omitempty"`
		// Carries "disputed" and friends. Two bytes on most records.
		CveTags []NvdCveTag `json:"cveTags,omitempty"`
		// Stored verbatim. Note this blob already carried CVSS v2, v4.0
		// and CISA's SSVC decision points long before anything read
		// them out — see extractCvssScore and extractSsvc.
		Metrics json.RawMessage `json:"metrics"`
		// Kept verbatim so the app can render NVD's own prose and CWE
		// mappings (descriptions filtered to English at save time —
		// see englishOnly).
		Descriptions []NvdDescription `json:"descriptions,omitempty"`
		Weaknesses   json.RawMessage  `json:"weaknesses,omitempty"`
		// Advisory / patch / exploit links, trimmed to url+tags at save
		// time (see trimReferences). Previously dropped on the grounds
		// that the app sources references from OSV — but OSV covers
		// package-ecosystem advisories and holds a record for only 8.2%
		// of the CVEs in this lake. For the other 91.8% there was no
		// link to an advisory, patch or exploit anywhere in it.
		References []NvdReference `json:"references,omitempty"`
		// Applicability. Parsed and exploded into cve_cpe, then cleared
		// before the record is stored — the rows are what queries need
		// and the blob would roughly triple cve_enriched for nothing.
		// Dropping this outright was the reason nothing in the lake
		// could answer "which CVEs affect FortiOS 7.2.4".
		//
		// NVD 2.0 also ships an `affected` array, deliberately NOT
		// parsed: it is CNA-submitted free text, overwhelmingly
		// {"vendor":"n/a","product":"n/a"}, and in a 2,000-record
		// sample only 17 records carried it without configurations.
		// It would cost more storage than every field added alongside
		// it here combined, for almost nothing over cve_cpe.
		Configurations []NvdConfiguration `json:"configurations,omitempty"`
	} `json:"cve"`
}

// NvdCveTag is one CNA's tag set for a CVE, e.g.
// {"sourceIdentifier": "cve@mitre.org", "tags": ["disputed"]}.
type NvdCveTag struct {
	SourceIdentifier string   `json:"sourceIdentifier"`
	Tags             []string `json:"tags"`
}

// NvdReference is one advisory link. NVD also sends `source` (the CNA
// that contributed the link); it is dropped at save time, where it
// duplicates sourceIdentifier for most rows and costs 28% of the
// reference bytes.
type NvdReference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags,omitempty"`
}

// NvdConfiguration is one applicability statement. NVD nests
// configurations[].nodes[].cpeMatch[]; the AND/OR logic between nodes
// expresses "vulnerable only when running on X", which we deliberately
// flatten — a customer asking "am I affected" is better served by a
// candidate they can dismiss than by a silent omission.
type NvdConfiguration struct {
	Nodes []struct {
		Operator string        `json:"operator"`
		Negate   bool          `json:"negate"`
		CpeMatch []NvdCpeMatch `json:"cpeMatch"`
	} `json:"nodes"`
}

type NvdCpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// cpeRow is a flattened cpeMatch ready for insert.
type cpeRow struct {
	part, vendor, product, version, update string
	startIncl, startExcl, endIncl, endExcl string
	vulnerable                             bool
	criteria, matchID                      string
}

// parseCpe23 splits a CPE 2.3 formatted string. The format is
// cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:... with colons
// inside components escaped as \:. Returns ok=false for anything that
// is not a well-formed 2.3 URI rather than guessing.
func parseCpe23(criteria string) (part, vendor, product, version, update string, ok bool) {
	if !strings.HasPrefix(criteria, "cpe:2.3:") {
		return "", "", "", "", "", false
	}
	var fields []string
	var cur strings.Builder
	escaped := false
	for _, r := range criteria[len("cpe:2.3:"):] {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			cur.WriteRune(r)
			escaped = true
		case r == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	fields = append(fields, cur.String())
	if len(fields) < 5 {
		return "", "", "", "", "", false
	}
	return fields[0], fields[1], fields[2], fields[3], fields[4], true
}

// flattenCpe walks configurations[].nodes[].cpeMatch[] into rows,
// dropping non-vulnerable entries (those describe the platform the
// vulnerable thing runs on, not the vulnerable thing) and de-duplicating
// identical nodes, which NVD does emit.
func flattenCpe(configs []NvdConfiguration) []cpeRow {
	seen := map[string]struct{}{}
	rows := make([]cpeRow, 0, 8)
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			if node.Negate {
				continue
			}
			for _, m := range node.CpeMatch {
				if !m.Vulnerable {
					continue
				}
				part, vendor, product, version, update, ok := parseCpe23(m.Criteria)
				if !ok || vendor == "" || product == "" {
					continue
				}
				key := m.Criteria + "|" + m.VersionStartIncluding + "|" + m.VersionStartExcluding +
					"|" + m.VersionEndIncluding + "|" + m.VersionEndExcluding
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				rows = append(rows, cpeRow{
					part: part, vendor: vendor, product: product,
					version: version, update: update,
					startIncl: m.VersionStartIncluding, startExcl: m.VersionStartExcluding,
					endIncl: m.VersionEndIncluding, endExcl: m.VersionEndExcluding,
					vulnerable: true, criteria: m.Criteria, matchID: m.MatchCriteriaID,
				})
			}
		}
	}
	return rows
}

// englishOnly keeps the English description(s) — NVD ships es/fr
// translations that would roughly double stored prose for no reader.
func englishOnly(descs []NvdDescription) []NvdDescription {
	var out []NvdDescription
	for _, d := range descs {
		if d.Lang == "en" {
			out = append(out, d)
		}
	}
	if out == nil && len(descs) > 0 {
		out = descs[:1]
	}
	return out
}

// trimReferences drops NVD's per-link `source` and any link with no
// URL. References run ~7.2 per CVE; keeping url+tags is 72% of the
// full bytes, and `source` is the CNA that contributed the link, which
// sourceIdentifier already carries for the record as a whole.
//
// The tags are worth keeping in full: "Patch", "Exploit" and
// "Vendor Advisory" are exactly what makes a link worth surfacing over
// its six siblings.
func trimReferences(refs []NvdReference) []NvdReference {
	if len(refs) == 0 {
		return nil
	}
	out := make([]NvdReference, 0, len(refs))
	for _, r := range refs {
		if r.URL == "" {
			continue
		}
		out = append(out, NvdReference{URL: r.URL, Tags: r.Tags})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// flattenCveTags collapses cveTags[].tags across every contributing CNA
// into one deduplicated set, so a filter is `'disputed' = ANY(cve_tags)`
// rather than a nested jsonb walk. Which CNA raised the tag is not kept:
// for a "should this finding be shown" decision the tag is what matters,
// not who applied it.
func flattenCveTags(tags []NvdCveTag) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 2)
	for _, t := range tags {
		for _, v := range t.Tags {
			if v == "" {
				continue
			}
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Helper to extract the full raw JSON of the item since we can't easily Unmarshal into itself
// In a real optimized scenario we might use a custom unmarshaler or map[string]interface{}.
// For simplicity, we will just marshal the struct back to JSON or keep it as byte slice if we can.
// Actually, since we want to store the "cve" part of the item, we can just use the Cve field above
// and when inserting, marshal it again.

type NvdRunner struct {
	db     *pgxpool.Pool
	cfg    config.NvdConfig
	client *http.Client
}

func NewNvdRunner(db *pgxpool.Pool, cfg config.NvdConfig) *NvdRunner {
	return &NvdRunner{
		db:  db,
		cfg: cfg,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (r *NvdRunner) Run(ctx context.Context) error {
	if !r.cfg.Enabled {
		slog.Info("NVD ingestion disabled")
		return nil
	}

	start := time.Now()
	defer func() {
		metrics.NvdRunDuration.Observe(time.Since(start).Seconds())
	}()

	// 1. Get Cursor
	cursor, err := r.getCursor(ctx)
	if err != nil {
		return fmt.Errorf("failed to get NVD cursor: %w", err)
	}

	startDt, err := time.Parse(time.RFC3339, cursor)
	if err != nil {
		slog.Warn("Invalid NVD cursor, resetting to 2000-01-01", "cursor", cursor, "error", err)
		startDt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	now := time.Now().UTC()

	// Record cursor lag
	metrics.NvdCursorLag.Set(now.Sub(startDt).Seconds())

	// NVD Max window is 120 days
	maxWindow := 120 * 24 * time.Hour

	for startDt.Before(now) {
		endDt := startDt.Add(maxWindow)
		if endDt.After(now) {
			endDt = now
		}

		slog.Info("Processing NVD window", "start", startDt, "end", endDt)

		if err := r.processWindow(ctx, startDt, endDt); err != nil {
			return err
		}

		// Update cursor
		if err := r.setCursor(ctx, endDt.Format(time.RFC3339)); err != nil {
			return fmt.Errorf("failed to update cursor: %w", err)
		}

		startDt = endDt

		// Update cursor lag as we catch up
		metrics.NvdCursorLag.Set(now.Sub(startDt).Seconds())
	}

	slog.Info("NVD ingestion complete")
	return nil
}

func (r *NvdRunner) processWindow(ctx context.Context, start, end time.Time) error {
	startIndex := 0
	pageSize := r.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 2000
	}

	// Format times for API
	// NVD expects ISO8601/RFC3339.
	startStr := start.Format(time.RFC3339)
	endStr := end.Format(time.RFC3339)

	for {
		// Construct URL
		baseURL := r.cfg.URL
		if baseURL == "" {
			baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
		}
		u, err := url.Parse(baseURL)
		if err != nil {
			return fmt.Errorf("invalid NVD URL %q: %w", baseURL, err)
		}
		q := u.Query()
		q.Set("pubStartDate", startStr)
		q.Set("pubEndDate", endStr)
		q.Set("resultsPerPage", strconv.Itoa(pageSize))
		q.Set("startIndex", strconv.Itoa(startIndex))
		u.RawQuery = q.Encode()

		// Fetch
		respData, err := r.fetchWithRetry(ctx, u.String())
		if err != nil {
			return fmt.Errorf("failed to fetch NVD page: %w", err)
		}

		// Parse
		var resp NvdResponse
		if err := json.Unmarshal(respData, &resp); err != nil {
			return fmt.Errorf("failed to parse NVD response: %w", err)
		}

		if len(resp.Vulnerabilities) == 0 {
			break
		}

		// Save Batch
		if err := r.saveBatch(ctx, resp.Vulnerabilities); err != nil {
			return fmt.Errorf("failed to save batch: %w", err)
		}

		metrics.NvdBatchSize.Observe(float64(len(resp.Vulnerabilities)))
		metrics.NvdCvesProcessed.Add(float64(len(resp.Vulnerabilities)))

		// Log progress
		slog.Info("Processed NVD batch", "start_index", startIndex, "count", len(resp.Vulnerabilities), "total_in_window", resp.TotalResults)

		startIndex += len(resp.Vulnerabilities)
		if startIndex >= resp.TotalResults {
			break
		}

		// Rate limit
		// NVD recommends sleeping. With API key, limits are higher (50 req/30s rolling window -> ~0.6s)
		// Without API key, limits are stricter (5 req/30s -> ~6s)
		delay := 6 * time.Second
		if r.cfg.ApiKey != "" {
			delay = 600 * time.Millisecond
		}
		time.Sleep(delay)
	}

	return nil
}

func (r *NvdRunner) fetchWithRetry(ctx context.Context, urlStr string) ([]byte, error) {
	backoff := 6 * time.Second
	const maxRetries = 10

	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			return nil, err
		}

		// Add API Key header if configured
		if r.cfg.ApiKey != "" {
			req.Header.Set("apiKey", r.cfg.ApiKey)
		}
		req.Header.Set("User-Agent", "tigerfetch/1.0 (+https://tigerblue.app)")

		httpStart := time.Now()
		resp, err := r.client.Do(req)
		if err != nil {
			metrics.UpstreamRequestDuration.WithLabelValues("nvd").Observe(time.Since(httpStart).Seconds())
			metrics.NvdFetches.WithLabelValues("error").Inc()
			slog.Warn("NVD fetch failed, retrying", "url", urlStr, "error", err, "attempt", attempt+1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}
		metrics.UpstreamRequestDuration.WithLabelValues("nvd").Observe(time.Since(httpStart).Seconds())

		if resp.StatusCode == http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			metrics.NvdFetches.WithLabelValues("success").Inc()
			return body, nil
		}
		_ = resp.Body.Close()

		// Check for 429 or 503
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			metrics.NvdRateLimits.Inc()
			slog.Warn("NVD rate limited or unavailable", "status", resp.StatusCode, "attempt", attempt+1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 1*time.Minute {
				backoff = 1 * time.Minute
			}
			continue
		}

		metrics.NvdApiErrors.WithLabelValues(strconv.Itoa(resp.StatusCode)).Inc()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil, fmt.Errorf("NVD fetch failed after %d retries: %s", maxRetries, urlStr)
}

func (r *NvdRunner) saveBatch(ctx context.Context, items []NvdCveItem) error {
	batch := &pgx.Batch{}
	queued := 0

	for _, item := range items {
		item.Cve.Descriptions = englishOnly(item.Cve.Descriptions)

		// Explode applicability into rows, then clear it: cve_cpe is
		// what queries use, and keeping the blob as well would roughly
		// triple this column for no reader. Delete-then-insert per CVE
		// rather than upsert, so an applicability statement NVD has
		// REMOVED disappears here too.
		cpeRows := flattenCpe(item.Cve.Configurations)
		item.Cve.Configurations = nil
		batch.Queue(`DELETE FROM cve_cpe WHERE cve_id = $1`, item.Cve.ID)
		queued++
		for _, c := range cpeRows {
			batch.Queue(`
				INSERT INTO cve_cpe (
					cve_id, part, vendor, product, version, update_field,
					version_start_including, version_start_excluding,
					version_end_including, version_end_excluding,
					vulnerable, criteria, match_criteria_id)
				VALUES ($1,$2,$3,$4,$5,$6,
					NULLIF($7,''), NULLIF($8,''), NULLIF($9,''), NULLIF($10,''),
					$11,$12,NULLIF($13,''))
			`, item.Cve.ID, c.part, c.vendor, c.product, c.version, c.update,
				c.startIncl, c.startExcl, c.endIncl, c.endExcl,
				c.vulnerable, c.criteria, c.matchID)
			queued++
			metrics.NvdCpeRows.Inc()
		}

		// Advisory links, minus the per-link `source`.
		item.Cve.References = trimReferences(item.Cve.References)

		// Convert the cve struct back to JSON for storage
		cveJSON, err := json.Marshal(item.Cve)
		if err != nil {
			slog.Error("Failed to marshal CVE item", "id", item.Cve.ID, "error", err)
			continue
		}

		// Parse modified time. NVD's format is not RFC3339 — see
		// parseNvdTime. Fall back to now() only so the row still lands;
		// it is logged, because a silent fallback here is exactly how
		// this column came to hold ingest times for every row.
		modified, ok := parseNvdTime(item.Cve.LastModified)
		if !ok {
			slog.Warn("Unparseable NVD lastModified, using ingest time",
				"id", item.Cve.ID, "value", item.Cve.LastModified)
			modified = time.Now().UTC()
		}

		// published is left NULL rather than defaulted: "unknown" is a
		// truthful answer, and a fabricated publication date would
		// quietly corrupt every "new this week" query built on it.
		var published *time.Time
		if p, ok := parseNvdTime(item.Cve.Published); ok {
			published = &p
		}

		m := parseMetrics(item.Cve.Metrics)
		if m.CvssBase == nil {
			metrics.NvdCvesWithoutCvss.Inc()
		}

		batch.Queue(`
			INSERT INTO cve_enriched (
				cve_id, source, json, cvss_base, modified,
				published, vuln_status, source_identifier, cve_tags,
				cvss_version, ssvc_exploitation, ssvc_automatable,
				ssvc_technical_impact)
			VALUES ($1, 'NVD', $2, $3, $4,
				$5, NULLIF($6,''), NULLIF($7,''), $8,
				NULLIF($9,''), NULLIF($10,''), NULLIF($11,''),
				NULLIF($12,''))
			ON CONFLICT (cve_id, source)
			DO UPDATE SET
				json                  = EXCLUDED.json,
				cvss_base             = EXCLUDED.cvss_base,
				modified              = EXCLUDED.modified,
				published             = EXCLUDED.published,
				vuln_status           = EXCLUDED.vuln_status,
				source_identifier     = EXCLUDED.source_identifier,
				cve_tags              = EXCLUDED.cve_tags,
				cvss_version          = EXCLUDED.cvss_version,
				ssvc_exploitation     = EXCLUDED.ssvc_exploitation,
				ssvc_automatable      = EXCLUDED.ssvc_automatable,
				ssvc_technical_impact = EXCLUDED.ssvc_technical_impact
		`, item.Cve.ID, cveJSON, m.CvssBase, modified,
			published, item.Cve.VulnStatus, item.Cve.SourceIdentifier,
			flattenCveTags(item.Cve.CveTags),
			m.CvssVersion, m.SsvcExploitation, m.SsvcAutomatable,
			m.SsvcTechnicalImpact)
		queued++
	}

	br := r.db.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()

	for i := 0; i < queued; i++ {
		_, err := br.Exec()
		if err != nil {
			return fmt.Errorf("batch execution failed at index %d: %w", i, err)
		}
	}

	return nil
}

// nvdMetrics is everything worth pulling out of the metrics blob. The
// blob itself is still stored verbatim; these are the fields promoted
// to columns so they can be filtered and indexed.
type nvdMetrics struct {
	CvssBase    *float64
	CvssVersion string // "3.1" | "3.0" | "4.0" | "2.0"

	// CISA SSVC v2.0.3 decision points. Present on ~45% of NVD records
	// and never previously read, though they were being stored all
	// along: exploitation=active is an exploitation assertion from CISA
	// that corroborates the KEV catalogue from a different direction.
	SsvcExploitation    string // none | poc | active
	SsvcAutomatable     string // no | yes
	SsvcTechnicalImpact string // partial | total
}

// parseMetrics decodes the metrics blob once. Preference order for the
// base score is v3.1 → v3.0 → v4.0 → v2.0.
//
// v4.0 sits below v3.x deliberately: NVD is still dual-publishing, and
// while CNAs migrate, ranking v4.0 first would make scores jump around
// between adjacent CVEs for no analytical gain. It sits above v2.0
// because a current-generation score beats a 2007 one.
//
// v2.0 last, and never silently: a v2 base score is NOT comparable to
// a v3 one (different formula, different meaning of 7.5), which is why
// CvssVersion is recorded alongside. 70,872 rows in this lake had a v2
// score and a NULL cvss_base — visibly wrong beats invisibly absent,
// but only if the consumer can see which scale it is reading.
func parseMetrics(metricsRaw json.RawMessage) nvdMetrics {
	var out nvdMetrics
	if len(metricsRaw) == 0 {
		return out
	}

	// BaseScore is a pointer so an entry that exists without a score is
	// distinguishable from a genuine 0.0 (which CVSS does define).
	type cvssData struct {
		BaseScore *float64 `json:"baseScore"`
	}
	type cvssMetric struct {
		CvssData cvssData `json:"cvssData"`
	}
	type ssvcEntry struct {
		SsvcData struct {
			// Each option is a single-key object:
			// [{"exploitation":"active"},{"automatable":"no"}]
			Options []map[string]string `json:"options"`
		} `json:"ssvcData"`
	}
	type metrics struct {
		CvssMetricV31 []cvssMetric `json:"cvssMetricV31"`
		CvssMetricV30 []cvssMetric `json:"cvssMetricV30"`
		CvssMetricV40 []cvssMetric `json:"cvssMetricV40"`
		CvssMetricV2  []cvssMetric `json:"cvssMetricV2"`
		SsvcV203      []ssvcEntry  `json:"ssvcV203"`
	}

	var m metrics
	if err := json.Unmarshal(metricsRaw, &m); err != nil {
		return out
	}

	for _, c := range []struct {
		entries []cvssMetric
		version string
	}{
		{m.CvssMetricV31, "3.1"},
		{m.CvssMetricV30, "3.0"},
		{m.CvssMetricV40, "4.0"},
		{m.CvssMetricV2, "2.0"},
	} {
		if len(c.entries) > 0 && c.entries[0].CvssData.BaseScore != nil {
			score := *c.entries[0].CvssData.BaseScore
			out.CvssBase = &score
			out.CvssVersion = c.version
			break
		}
	}

	if len(m.SsvcV203) > 0 {
		for _, opt := range m.SsvcV203[0].SsvcData.Options {
			if v, ok := opt["exploitation"]; ok && out.SsvcExploitation == "" {
				out.SsvcExploitation = v
			}
			if v, ok := opt["automatable"]; ok && out.SsvcAutomatable == "" {
				out.SsvcAutomatable = v
			}
			if v, ok := opt["technicalImpact"]; ok && out.SsvcTechnicalImpact == "" {
				out.SsvcTechnicalImpact = v
			}
		}
	}

	return out
}

// extractCvssScore returns just the base score. Retained as the narrow
// accessor for callers and tests that do not care which scale it came
// from — check parseMetrics().CvssVersion when they should.
func extractCvssScore(metricsRaw json.RawMessage) *float64 {
	return parseMetrics(metricsRaw).CvssBase
}

// nvdTimeLayouts are the shapes NVD 2.0 actually emits for `published`
// and `lastModified`. They are NOT RFC3339: the API sends a naive
// "2026-08-29T18:16:33.473" with no Z and no offset, documented as UTC.
//
// This matters more than it looks. Parsing these as RFC3339 fails for
// EVERY record, and the previous fallback silently substituted
// time.Now() — so cve_enriched.modified held the ingest time rather
// than NVD's modification time on all 382,817 rows, and "what changed
// upstream" was unanswerable while looking perfectly plausible.
var nvdTimeLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05",
}

// parseNvdTime parses an NVD timestamp as UTC. ok is false for an empty
// or unparseable value, so callers can store NULL rather than invent a
// time — a wrong timestamp is worse than a missing one here.
func parseNvdTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range nvdTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func (r *NvdRunner) getCursor(ctx context.Context) (string, error) {
	var cursor string
	err := r.db.QueryRow(ctx, "SELECT cursor FROM ingest_state WHERE source = 'NVD'").Scan(&cursor)
	if err == pgx.ErrNoRows {
		// Default start date: 2000-01-01
		return "2000-01-01T00:00:00Z", nil
	}
	if err != nil {
		return "", err
	}
	return cursor, nil
}

func (r *NvdRunner) setCursor(ctx context.Context, cursor string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO ingest_state (source, cursor) VALUES ('NVD', $1)
		ON CONFLICT (source) DO UPDATE SET cursor = EXCLUDED.cursor
	`, cursor)
	return err
}
