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
	"time"

	"tiger2go/internal/config"

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

type NvdCveItem struct {
	Cve struct {
		ID           string          `json:"id"`
		LastModified string          `json:"lastModified"`
		Metrics      json.RawMessage `json:"metrics"`
		// We capture the whole raw CVE object for storage,
		// but unmarshal specific fields for indexing.
	} `json:"cve"`
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
		u, _ := url.Parse(baseURL)
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
	var backoff time.Duration = 6 * time.Second

	for {
		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			return nil, err
		}

		// Add API Key header if configured
		if r.cfg.ApiKey != "" {
			req.Header.Set("apiKey", r.cfg.ApiKey)
		}
		req.Header.Set("User-Agent", "tigerfetch/1.0 (+https://tigerblue.app)")

		resp, err := r.client.Do(req)
		if err != nil {
			slog.Warn("NVD fetch failed, retrying", "url", urlStr, "error", err)
			time.Sleep(backoff)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return io.ReadAll(resp.Body)
		}

		// Check for 429 or 503
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			slog.Warn("NVD rate limited or unavailable", "status", resp.StatusCode)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > 1*time.Minute {
				backoff = 1 * time.Minute
			}
			continue
		}

		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (r *NvdRunner) saveBatch(ctx context.Context, items []NvdCveItem) error {
	batch := &pgx.Batch{}

	for _, item := range items {
		// Convert the cve struct back to JSON for storage
		cveJSON, err := json.Marshal(item.Cve)
		if err != nil {
			slog.Error("Failed to marshal CVE item", "id", item.Cve.ID, "error", err)
			continue
		}

		// Parse modified time
		modified, err := time.Parse(time.RFC3339, item.Cve.LastModified)
		if err != nil {
			modified = time.Now()
		}

		// Extract CVSS Base Score (V3.1 prefered)
		var cvssBase *float64
		// We need to parse the metrics raw JSON to find the base score. Note: This is a bit ugly.
		// Structure: metrics: { "cvssMetricV31": [ { "cvssData": { "baseScore": 9.8 } } ] }
		cvssBase = extractCvssScore(item.Cve.Metrics)

		batch.Queue(`
			INSERT INTO cve_enriched (cve_id, source, json, cvss_base, modified)
			VALUES ($1, 'NVD', $2, $3, $4)
			ON CONFLICT (cve_id, source)
			DO UPDATE SET 
				json = EXCLUDED.json,
				cvss_base = EXCLUDED.cvss_base,
				modified = EXCLUDED.modified
		`, item.Cve.ID, cveJSON, cvssBase, modified)
	}

	br := r.db.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(items); i++ {
		_, err := br.Exec()
		if err != nil {
			return fmt.Errorf("batch execution failed at index %d: %w", i, err)
		}
	}

	return nil
}

// extractCvssScore tries to extract CVSS V3.1 or V3.0 base score
func extractCvssScore(metricsRaw json.RawMessage) *float64 {
	if len(metricsRaw) == 0 {
		return nil
	}

	// Simple structure for parsing just what we need
	type CvssData struct {
		BaseScore float64 `json:"baseScore"`
	}
	type CvssMetric struct {
		CvssData CvssData `json:"cvssData"`
	}
	type Metrics struct {
		CvssMetricV31 []CvssMetric `json:"cvssMetricV31"`
		CvssMetricV30 []CvssMetric `json:"cvssMetricV30"`
	}

	var m Metrics
	if err := json.Unmarshal(metricsRaw, &m); err != nil {
		return nil
	}

	if len(m.CvssMetricV31) > 0 {
		return &m.CvssMetricV31[0].CvssData.BaseScore
	}
	if len(m.CvssMetricV30) > 0 {
		return &m.CvssMetricV30[0].CvssData.BaseScore
	}
	return nil
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
