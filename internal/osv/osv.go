// Package osv ingests advisories from the OSV (Open Source Vulnerabilities)
// project — https://osv.dev. Each supported ecosystem (PyPI, npm, Go, Maven,
// RubyGems, crates.io, …) is published as an `all.zip` bundle of per-advisory
// JSON files under `osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip`.
//
// The runner downloads each configured ecosystem's bundle, parses every JSON
// file inside, and upserts into `osv_vulns`. Idempotent — re-fetching a bundle
// with no new advisories produces zero row changes (modified timestamp is the
// ON CONFLICT discriminator).
//
// Schema reference: https://ossf.github.io/osv-schema/
package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// Vulnerability is a subset of the OSV schema covering the fields we
// denormalise into columns. The full record is preserved verbatim in the
// `raw` jsonb column.
type Vulnerability struct {
	SchemaVersion string          `json:"schema_version"`
	ID            string          `json:"id"`
	Aliases       []string        `json:"aliases,omitempty"`
	Related       []string        `json:"related,omitempty"`
	Summary       string          `json:"summary,omitempty"`
	Details       string          `json:"details,omitempty"`
	Published     string          `json:"published,omitempty"`
	Modified      string          `json:"modified,omitempty"`
	Withdrawn     string          `json:"withdrawn,omitempty"`
	Affected      []Affected      `json:"affected,omitempty"`
	References    json.RawMessage `json:"references,omitempty"`
	Severity      []Severity      `json:"severity,omitempty"`
}

type Affected struct {
	Package Package `json:"package"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Runner polls the OSV bundles for each configured ecosystem.
type Runner struct {
	db     *pgxpool.Pool
	cfg    config.OsvConfig
	client *http.Client
}

func NewRunner(db *pgxpool.Pool, cfg config.OsvConfig) *Runner {
	return &Runner{
		db:  db,
		cfg: cfg,
		client: &http.Client{
			Timeout: 5 * time.Minute, // bundles can be 50–100 MB
		},
	}
}

// Run downloads each configured ecosystem's bundle and upserts every advisory.
func (r *Runner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("OSV ingestion disabled")
		return nil
	}
	if len(r.cfg.Ecosystems) == 0 {
		slog.Warn("OSV enabled but no ecosystems configured — skipping")
		return nil
	}

	start := time.Now()
	defer func() {
		metrics.OsvRunDuration.Observe(time.Since(start).Seconds())
	}()

	baseURL := r.cfg.URL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	var firstErr error
	for _, eco := range r.cfg.Ecosystems {
		if err := r.ingestEcosystem(ctx, baseURL, eco); err != nil {
			slog.Error("OSV ecosystem ingest failed", "ecosystem", eco, "error", err)
			metrics.OsvFetches.WithLabelValues(eco, "error").Inc()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		metrics.OsvFetches.WithLabelValues(eco, "success").Inc()
	}
	return firstErr
}

func (r *Runner) ingestEcosystem(ctx context.Context, baseURL, ecosystem string) error {
	url := fmt.Sprintf("%s/%s/all.zip", strings.TrimRight(baseURL, "/"), ecosystem)
	slog.Info("OSV fetching bundle", "ecosystem", ecosystem, "url", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}

	processed, err := r.persistBundle(ctx, ecosystem, zr)
	if err != nil {
		return err
	}
	metrics.OsvVulnsProcessed.WithLabelValues(ecosystem).Add(float64(processed))
	slog.Info("OSV ecosystem ingest complete", "ecosystem", ecosystem, "advisories", processed)
	return nil
}

func (r *Runner) persistBundle(ctx context.Context, ecosystem string, zr *zip.Reader) (int, error) {
	const upsertSQL = `
		INSERT INTO osv_vulns (
			id, schema_version, ecosystem, package_names, summary, details,
			aliases, related, affected, refs, severity, cvss_v3,
			published, modified, withdrawn, raw, last_seen_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9::jsonb, $10::jsonb, $11::jsonb, $12,
			$13, $14, $15, $16::jsonb, now()
		)
		ON CONFLICT (id) DO UPDATE SET
			schema_version = EXCLUDED.schema_version,
			ecosystem      = EXCLUDED.ecosystem,
			package_names  = EXCLUDED.package_names,
			summary        = EXCLUDED.summary,
			details        = EXCLUDED.details,
			aliases        = EXCLUDED.aliases,
			related        = EXCLUDED.related,
			affected       = EXCLUDED.affected,
			refs           = EXCLUDED.refs,
			severity       = EXCLUDED.severity,
			cvss_v3        = EXCLUDED.cvss_v3,
			published      = EXCLUDED.published,
			modified       = EXCLUDED.modified,
			withdrawn      = EXCLUDED.withdrawn,
			raw            = EXCLUDED.raw,
			last_seen_at   = now()
		WHERE osv_vulns.modified IS DISTINCT FROM EXCLUDED.modified
		   OR osv_vulns.withdrawn IS DISTINCT FROM EXCLUDED.withdrawn`

	processed := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		select {
		case <-ctx.Done():
			return processed, ctx.Err()
		default:
		}

		rec, raw, err := readAdvisory(f)
		if err != nil {
			slog.Warn("OSV skipping malformed advisory", "file", f.Name, "error", err)
			continue
		}

		published := parseTime(rec.Published)
		modified := parseTime(rec.Modified)
		withdrawn := parseTime(rec.Withdrawn)
		pkgNames := extractPackageNames(rec)
		cvss := extractCvssV3(rec.Severity)

		_, err = r.db.Exec(ctx, upsertSQL,
			rec.ID, rec.SchemaVersion, ecosystem, pkgNames, rec.Summary, rec.Details,
			rec.Aliases, rec.Related, mustMarshal(rec.Affected), rec.References, mustMarshal(rec.Severity), cvss,
			published, modified, withdrawn, raw,
		)
		if err != nil {
			return processed, fmt.Errorf("upsert %s: %w", rec.ID, err)
		}
		processed++
	}
	return processed, nil
}

func readAdvisory(f *zip.File) (Vulnerability, []byte, error) {
	rc, err := f.Open()
	if err != nil {
		return Vulnerability{}, nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = rc.Close() }()

	raw, err := io.ReadAll(rc)
	if err != nil {
		return Vulnerability{}, nil, fmt.Errorf("read: %w", err)
	}
	var rec Vulnerability
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Vulnerability{}, nil, fmt.Errorf("unmarshal: %w", err)
	}
	return rec, raw, nil
}

func extractPackageNames(v Vulnerability) []string {
	if len(v.Affected) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(v.Affected))
	out := make([]string, 0, len(v.Affected))
	for _, a := range v.Affected {
		name := strings.TrimSpace(a.Package.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

// extractCvssV3 returns the numeric score from the first CVSS_V3 entry in
// the severity[] slice, or nil if none. The OSV schema permits two shapes:
//
//   - Vector form ending with the score:  "CVSS:3.1/AV:N/.../A:H/9.8"
//   - Bare numeric:                       "9.8"
//
// In practice most OSV severity entries (notably PyPI advisories sourced
// from GHSA) publish ONLY the vector with no trailing numeric — the consumer
// is expected to compute the score from the vector. Until we add a proper
// CVSS-vector evaluator, those advisories will leave cvss_v3 NULL; the full
// vector remains queryable via the `severity` jsonb column.
func extractCvssV3(sev []Severity) *float64 {
	for _, s := range sev {
		if !strings.EqualFold(s.Type, "CVSS_V3") {
			continue
		}
		score := s.Score
		if idx := strings.LastIndex(score, "/"); idx >= 0 {
			score = score[idx+1:]
		}
		var f float64
		if _, err := fmt.Sscanf(strings.TrimSpace(score), "%f", &f); err == nil {
			return &f
		}
	}
	return nil
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

func mustMarshal(v any) []byte {
	if v == nil {
		return []byte("null")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}
