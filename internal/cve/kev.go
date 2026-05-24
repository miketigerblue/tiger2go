package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

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
	// CISA uses "Known" / "Unknown" for this field. Stored as-is so the
	// downstream cve_kev backfill can compute the boolean (and any
	// future field-value drift remains visible in the raw JSON).
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
	// CWE identifiers tagged to the entry by CISA. Array of strings like ["CWE-77"].
	CWEs []string `json:"cwes"`
	// We capture the raw JSON for storage by re-marshaling the struct.
	// Adding a new upstream field means adding it here too, otherwise
	// it gets silently dropped on round-trip — that's how this very
	// file ended up missing knownRansomwareCampaignUse and cwes for
	// several months.
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

func (r *KevRunner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("KEV ingestion disabled")
		return nil
	}

	start := time.Now()
	defer func() {
		metrics.KevRunDuration.Observe(time.Since(start).Seconds())
		if retErr != nil {
			metrics.KevFetches.WithLabelValues("error").Inc()
		}
	}()

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

	// Record cursor lag
	if t, err := time.Parse(time.RFC3339, cursor); err == nil {
		metrics.KevCursorLag.Set(time.Since(t).Seconds())
	}

	existingCursor, err := r.getCursor(ctx)
	if err != nil {
		return fmt.Errorf("failed to get existing cursor: %w", err)
	}

	if existingCursor == cursor {
		slog.Info("KEV catalog up-to-date", "cursor", cursor)
		metrics.KevFetches.WithLabelValues("up_to_date").Inc()
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

	metrics.KevFetches.WithLabelValues("success").Inc()
	metrics.KevVulnsProcessed.Add(float64(len(catalog.Vulnerabilities)))
	slog.Info("KEV ingestion complete")
	return nil
}

func (r *KevRunner) fetchCatalog(ctx context.Context, url string) (*KevCatalog, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tigerfetch/1.0 (+https://tigerblue.app)")

	httpStart := time.Now()
	resp, err := r.client.Do(req)
	metrics.UpstreamRequestDuration.WithLabelValues("kev").Observe(time.Since(httpStart).Seconds())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

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
	queuedPerVuln := 0 // 2 statements per vuln: cve_enriched + cve_kev
	queued := 0

	for _, v := range vulns {
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			slog.Error("Failed to marshal KEV vuln", "cve_id", v.CveID, "error", err)
			continue
		}

		// (1) cve_enriched — legacy source-keyed view; downstream tiger-eye joins on this.
		batch.Queue(`
			INSERT INTO cve_enriched (cve_id, source, json, modified)
			VALUES ($1, 'CISA-KEV', $2, $3)
			ON CONFLICT (cve_id, source)
			DO UPDATE SET
				json = EXCLUDED.json,
				modified = EXCLUDED.modified
		`, v.CveID, jsonBytes, modified)

		// (2) cve_kev — first-class typed columns. Mirror exactly the
		// projection used by scripts/backfill_cve_kev.sql so a re-run of
		// that script remains a no-op.
		batch.Queue(`
			INSERT INTO cve_kev (
				cve_id, vulnerability_name, vendor_project, product,
				short_description, required_action, date_added, due_date,
				known_ransomware_use, notes, cwes, raw, last_seen_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, now())
			ON CONFLICT (cve_id) DO UPDATE SET
				vulnerability_name   = EXCLUDED.vulnerability_name,
				vendor_project       = EXCLUDED.vendor_project,
				product              = EXCLUDED.product,
				short_description    = EXCLUDED.short_description,
				required_action      = EXCLUDED.required_action,
				date_added           = EXCLUDED.date_added,
				due_date             = EXCLUDED.due_date,
				known_ransomware_use = EXCLUDED.known_ransomware_use,
				notes                = EXCLUDED.notes,
				cwes                 = EXCLUDED.cwes,
				raw                  = EXCLUDED.raw,
				last_seen_at         = now()
		`,
			v.CveID,
			nilEmptyKev(v.VulnerabilityName),
			nilEmptyKev(v.VendorProject),
			nilEmptyKev(v.Product),
			nilEmptyKev(v.ShortDescription),
			nilEmptyKev(v.RequiredAction),
			parseKevDate(v.DateAdded),
			parseKevDate(v.DueDate),
			strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "known"),
			nilEmptyKev(v.Notes),
			v.CWEs,
			jsonBytes,
		)

		queued++
		queuedPerVuln = 2
	}

	br := r.db.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()

	for i := 0; i < queued*queuedPerVuln; i++ {
		_, err := br.Exec()
		if err != nil {
			return fmt.Errorf("batch execution failed at index %d: %w", i, err)
		}
	}

	return nil
}

// nilEmptyKev returns nil for empty/whitespace strings so DB columns
// store NULL rather than ''. Mirrors the NULLIF semantics in
// scripts/backfill_cve_kev.sql.
func nilEmptyKev(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

// parseKevDate parses the CISA YYYY-MM-DD date strings to a *time.Time
// that pgx writes as a DATE. Returns nil for unrecognised input — the
// backfill script's `~ '^\d{4}-\d{2}-\d{2}$'` regex guard inspired this.
func parseKevDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	return &t
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
