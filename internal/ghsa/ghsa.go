// Package ghsa ingests the GitHub Security Advisory Database via the public
// REST API at https://api.github.com/advisories.
//
// Each advisory has a stable GHSA-* id, an optional CVE alias, a numeric
// CVSS score (unlike OSV's vector-only encoding), a CWE list, and per-package
// vulnerability ranges. The runner uses incremental fetches via the
// `?modified=>{cursor}` filter — the first run pulls everything (~30K
// advisories), subsequent runs only the new/updated ones since the last
// `last_seen` cursor stored in `ingest_state`.
//
// API reference: https://docs.github.com/en/rest/security-advisories
package ghsa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultURL      = "https://api.github.com/advisories"
	defaultPageSize = 100
	cursorSource    = "GHSA"
	apiAcceptHeader = "application/vnd.github+json"
	apiVersion      = "2022-11-28"
)

// Advisory is the subset of the GHSA REST response we denormalise into
// indexed columns. The full record is preserved verbatim in osv_vulns.raw.
type Advisory struct {
	GhsaID          string          `json:"ghsa_id"`
	CveID           string          `json:"cve_id"`
	Summary         string          `json:"summary"`
	Description     string          `json:"description"`
	Severity        string          `json:"severity"`
	State           string          `json:"state"`
	Type            string          `json:"type"`
	Identifiers     []Identifier    `json:"identifiers"`
	References      []string        `json:"references"`
	PublishedAt     string          `json:"published_at"`
	UpdatedAt       string          `json:"updated_at"`
	WithdrawnAt     string          `json:"withdrawn_at"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	CvssSeverities  *CvssSeverities `json:"cvss_severities"`
	CWEs            []CWE           `json:"cwes"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Vulnerability struct {
	Package Package `json:"package"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type CvssSeverities struct {
	CvssV3 *CvssScore `json:"cvss_v3"`
	CvssV4 *CvssScore `json:"cvss_v4"`
}

type CvssScore struct {
	VectorString string   `json:"vector_string"`
	Score        *float64 `json:"score"`
}

type CWE struct {
	CweID string `json:"cwe_id"`
	Name  string `json:"name"`
}

type Runner struct {
	db     *pgxpool.Pool
	cfg    config.GhsaConfig
	client *http.Client
}

func NewRunner(db *pgxpool.Pool, cfg config.GhsaConfig) *Runner {
	return &Runner{
		db:  db,
		cfg: cfg,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (r *Runner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("GHSA ingestion disabled")
		return nil
	}

	start := time.Now()
	defer func() {
		metrics.GhsaRunDuration.Observe(time.Since(start).Seconds())
		if retErr != nil {
			metrics.GhsaFetches.WithLabelValues("error").Inc()
		} else {
			metrics.GhsaFetches.WithLabelValues("success").Inc()
		}
	}()

	cursor, err := r.readCursor(ctx)
	if err != nil {
		return fmt.Errorf("read cursor: %w", err)
	}

	pageSize := r.cfg.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = defaultPageSize
	}
	base := r.cfg.URL
	if base == "" {
		base = defaultURL
	}

	url := fmt.Sprintf(
		"%s?per_page=%d&sort=updated&direction=asc&modified=%%3E%s",
		base, pageSize, cursor.UTC().Format(time.RFC3339),
	)

	maxSeen := cursor
	total := 0
	// Persist whatever progress we made even if we return mid-loop (rate
	// limit / connection error). The cursor is the only signal that
	// stops the next run from re-fetching what we already have.
	defer func() {
		if maxSeen.After(cursor) {
			if err := r.writeCursor(context.Background(), maxSeen); err != nil {
				slog.Warn("GHSA cursor persist failed", "error", err)
			}
		}
	}()

	for url != "" {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, nextURL, err := r.fetchPage(ctx, url)
		if err != nil {
			return err
		}
		metrics.GhsaPagesFetched.Inc()

		for _, adv := range page {
			if err := r.upsert(ctx, adv); err != nil {
				return fmt.Errorf("upsert %s: %w", adv.GhsaID, err)
			}
			if t := parseTime(adv.UpdatedAt); t != nil && t.After(maxSeen) {
				maxSeen = *t
			}
			total++
		}
		metrics.GhsaAdvisoriesProcessed.Add(float64(len(page)))

		url = nextURL
	}

	slog.Info("GHSA ingestion complete", "advisories", total, "cursor", maxSeen.Format(time.RFC3339))
	return nil
}

func (r *Runner) fetchPage(ctx context.Context, url string) ([]Advisory, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", apiAcceptHeader)
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	if r.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		if n, err := strconv.ParseFloat(remaining, 64); err == nil {
			metrics.GhsaRateLimitRemaining.Set(n)
		}
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read body: %w", err)
	}

	var advs []Advisory
	if err := json.Unmarshal(body, &advs); err != nil {
		return nil, "", fmt.Errorf("unmarshal: %w", err)
	}

	return advs, parseNextLink(resp.Header.Get("Link")), nil
}

// parseNextLink finds the rel="next" URL in a GitHub Link header.
// Returns empty string when there's no next page.
func parseNextLink(link string) string {
	if link == "" {
		return ""
	}
	for _, part := range strings.Split(link, ",") {
		seg := strings.TrimSpace(part)
		if !strings.Contains(seg, `rel="next"`) {
			continue
		}
		if i := strings.Index(seg, "<"); i >= 0 {
			if j := strings.Index(seg[i+1:], ">"); j >= 0 {
				return seg[i+1 : i+1+j]
			}
		}
	}
	return ""
}

func (r *Runner) upsert(ctx context.Context, adv Advisory) error {
	const sql = `
		INSERT INTO ghsa_advisories (
			ghsa_id, cve_id, summary, description, severity,
			cvss_v3, cvss_v3_vector, cvss_v4, cvss_v4_vector,
			cwes, ecosystems, package_names,
			vulnerabilities, refs,
			published, updated, withdrawn,
			state, advisory_type, raw,
			last_seen_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13::jsonb, $14::jsonb,
			$15, $16, $17,
			$18, $19, $20::jsonb,
			now()
		)
		ON CONFLICT (ghsa_id) DO UPDATE SET
			cve_id          = EXCLUDED.cve_id,
			summary         = EXCLUDED.summary,
			description     = EXCLUDED.description,
			severity        = EXCLUDED.severity,
			cvss_v3         = EXCLUDED.cvss_v3,
			cvss_v3_vector  = EXCLUDED.cvss_v3_vector,
			cvss_v4         = EXCLUDED.cvss_v4,
			cvss_v4_vector  = EXCLUDED.cvss_v4_vector,
			cwes            = EXCLUDED.cwes,
			ecosystems      = EXCLUDED.ecosystems,
			package_names   = EXCLUDED.package_names,
			vulnerabilities = EXCLUDED.vulnerabilities,
			refs            = EXCLUDED.refs,
			published       = EXCLUDED.published,
			updated         = EXCLUDED.updated,
			withdrawn       = EXCLUDED.withdrawn,
			state           = EXCLUDED.state,
			advisory_type   = EXCLUDED.advisory_type,
			raw             = EXCLUDED.raw,
			last_seen_at    = now()
		WHERE ghsa_advisories.updated IS DISTINCT FROM EXCLUDED.updated`

	cve := adv.CveID
	if cve == "" {
		for _, id := range adv.Identifiers {
			if strings.EqualFold(id.Type, "CVE") {
				cve = id.Value
				break
			}
		}
	}

	var cvss3, cvss4 *float64
	var vec3, vec4 string
	if adv.CvssSeverities != nil {
		if adv.CvssSeverities.CvssV3 != nil {
			cvss3 = adv.CvssSeverities.CvssV3.Score
			vec3 = adv.CvssSeverities.CvssV3.VectorString
		}
		if adv.CvssSeverities.CvssV4 != nil {
			cvss4 = adv.CvssSeverities.CvssV4.Score
			vec4 = adv.CvssSeverities.CvssV4.VectorString
		}
	}

	raw, err := json.Marshal(adv)
	if err != nil {
		return fmt.Errorf("marshal raw: %w", err)
	}
	vulns, _ := json.Marshal(adv.Vulnerabilities)
	refs, _ := json.Marshal(adv.References)

	var cveArg interface{}
	if cve != "" {
		cveArg = cve
	}

	_, err = r.db.Exec(ctx, sql,
		adv.GhsaID, cveArg, adv.Summary, adv.Description, adv.Severity,
		cvss3, nilEmpty(vec3), cvss4, nilEmpty(vec4),
		extractCWEs(adv.CWEs), extractEcosystems(adv.Vulnerabilities), extractPackageNames(adv.Vulnerabilities),
		vulns, refs,
		parseTime(adv.PublishedAt), parseTime(adv.UpdatedAt), parseTime(adv.WithdrawnAt),
		nilEmpty(adv.State), nilEmpty(adv.Type), raw,
	)
	return err
}

func (r *Runner) readCursor(ctx context.Context) (time.Time, error) {
	var cur string
	err := r.db.QueryRow(ctx, "SELECT cursor FROM ingest_state WHERE source=$1", cursorSource).Scan(&cur)
	if err != nil {
		// Treat any error (no row, missing table during early bootstrap) as "no cursor yet"
		// and start from GHSA's birth date — published advisories began trickling in 2017.
		return time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC), nil //nolint:nilerr
	}
	if t, err := time.Parse(time.RFC3339, cur); err == nil {
		return t, nil
	}
	return time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC), nil
}

func (r *Runner) writeCursor(ctx context.Context, t time.Time) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO ingest_state (source, cursor)
		VALUES ($1, $2)
		ON CONFLICT (source) DO UPDATE SET cursor = EXCLUDED.cursor
	`, cursorSource, t.UTC().Format(time.RFC3339))
	return err
}

func extractCWEs(cwes []CWE) []string {
	out := make([]string, 0, len(cwes))
	for _, c := range cwes {
		if c.CweID != "" {
			out = append(out, c.CweID)
		}
	}
	return out
}

func extractEcosystems(vs []Vulnerability) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		e := strings.TrimSpace(v.Package.Ecosystem)
		if e == "" {
			continue
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out
}

func extractPackageNames(vs []Vulnerability) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		n := strings.TrimSpace(v.Package.Name)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

func nilEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
