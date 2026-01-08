package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"tiger2go/internal/config"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type KevCatalog struct {
	CatalogVersion  string    `json:"catalogVersion"`
	DateReleased    string    `json:"dateReleased"`
	Count           int       `json:"count"`
	Vulnerabilities []KevVuln `json:"vulnerabilities"`
}

type KevVuln struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
	// We capture the raw JSON for storage by re-marshaling the struct or using a map wrapper.
	// Since the fields are flat, re-marshaling is easy.
}

type KevRunner struct {
	db     *pgxpool.Pool
	cfg    config.KevConfig
	client *http.Client
}

func NewKevRunner(db *pgxpool.Pool, cfg config.KevConfig) *KevRunner {
	return &KevRunner{
		db:  db,
		cfg: cfg,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (r *KevRunner) Run(ctx context.Context) error {
	if !r.cfg.Enabled {
		slog.Info("KEV ingestion disabled")
		return nil
	}

	url := r.cfg.URL
	if url == "" {
		url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}

	// 1. Fetch Catalog
	slog.Info("Fetching KEV catalog", "url", url)
	catalog, err := r.fetchCatalog(ctx, url)
	if err != nil {
		return fmt.Errorf("failed to fetch KEV catalog: %w", err)
	}

	// 2. Check Cursor
	cursor := catalog.DateReleased // Prefer DateReleased as cursor
	if cursor == "" {
		cursor = catalog.CatalogVersion // Fallback
	}

	// Try to normalize date for cursor to ensure consistency
	if t, err := time.Parse(time.RFC3339, cursor); err == nil {
		cursor = t.Format(time.RFC3339)
	}

	existingCursor, err := r.getCursor(ctx)
	if err != nil {
		return fmt.Errorf("failed to get existing cursor: %w", err)
	}

	if existingCursor == cursor {
		slog.Info("KEV catalog up-to-date", "cursor", cursor)
		return nil
	}

	slog.Info("New KEV catalog found", "version", catalog.CatalogVersion, "date", catalog.DateReleased, "count", len(catalog.Vulnerabilities))

	// 3. Upsert Vulnerabilities
	if err := r.upsertVulns(ctx, catalog.Vulnerabilities, catalog.DateReleased); err != nil {
		return fmt.Errorf("failed to upsert KEV vulns: %w", err)
	}

	// 4. Update Cursor
	if err := r.setCursor(ctx, cursor); err != nil {
		return fmt.Errorf("failed to update cursor: %w", err)
	}

	slog.Info("KEV ingestion complete")
	return nil
}

func (r *KevRunner) fetchCatalog(ctx context.Context, url string) (*KevCatalog, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tigerfetch/1.0 (+https://tigerblue.app)")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	var catalog KevCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, err
	}
	return &catalog, nil
}

func (r *KevRunner) upsertVulns(ctx context.Context, vulns []KevVuln, dateReleased string) error {
	// Parse catalog date for 'modified' timestamp
	modified, err := time.Parse(time.RFC3339, dateReleased)
	if err != nil {
		modified = time.Now()
	}

	batch := &pgx.Batch{}

	for _, v := range vulns {
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			continue // Skip malformed
		}

		batch.Queue(`
			INSERT INTO cve_enriched (cve_id, source, json, modified)
			VALUES ($1, 'CISA-KEV', $2, $3)
			ON CONFLICT (cve_id, source)
			DO UPDATE SET 
				json = EXCLUDED.json,
				modified = EXCLUDED.modified
		`, v.CveID, jsonBytes, modified)
	}

	br := r.db.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(vulns); i++ {
		_, err := br.Exec()
		if err != nil {
			return fmt.Errorf("batch execution failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (r *KevRunner) getCursor(ctx context.Context) (string, error) {
	var cursor string
	err := r.db.QueryRow(ctx, "SELECT cursor FROM ingest_state WHERE source = 'CISA-KEV'").Scan(&cursor)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return cursor, nil
}

func (r *KevRunner) setCursor(ctx context.Context, cursor string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO ingest_state (source, cursor) VALUES ('CISA-KEV', $1)
		ON CONFLICT (source) DO UPDATE SET cursor = EXCLUDED.cursor
	`, cursor)
	return err
}
