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

type EpssRow struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

type EpssResponse struct {
	Status string    `json:"status"`
	Total  int       `json:"total"`
	Offset int       `json:"offset"`
	Limit  int       `json:"limit"`
	Data   []EpssRow `json:"data"`
}

// EpssRunner handles EPSS data ingestion.
type EpssRunner struct {
	db     *pgxpool.Pool
	cfg    config.EpssConfig
	client *http.Client
}

// NewEpssRunner creates a new instance of EpssRunner.
func NewEpssRunner(db *pgxpool.Pool, cfg config.EpssConfig) *EpssRunner {
	return &EpssRunner{
		db:  db,
		cfg: cfg,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Run starts the EPSS ingestion process.
func (r *EpssRunner) Run(ctx context.Context) error {
	if !r.cfg.Enabled {
		slog.Info("EPSS ingestion disabled")
		return nil
	}

	slog.Info("Starting EPSS ingestion")

	// 1. Fetch first page to get total and date
	pageSize := r.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 5000
	}

	url := fmt.Sprintf("%s?limit=%d&offset=0", r.cfg.URL, pageSize)

	resp, e := r.fetch(url)
	if e != nil {
		return fmt.Errorf("failed to fetch EPSS: %w", e)
	}

	if len(resp.Data) == 0 {
		slog.Info("No EPSS data returned")
		return nil
	}

	dateStr := resp.Data[0].Date
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return fmt.Errorf("failed to parse EPSS date %s: %w", dateStr, err)
	}

	// 2. Check if we already have this date
	// Note: Schema uses 'as_of' column, not 'date'
	var exists bool
	err = r.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM epss_daily WHERE as_of = $1 LIMIT 1)", date).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check existing EPSS date: %w", err)
	}

	if exists {
		slog.Info("EPSS data for date already exists, skipping", "date", dateStr)
		return nil
	}

	// 3. Ensure partition exists
	if err := r.ensurePartition(ctx, date); err != nil {
		return err
	}

	// 4. Ingest Loop
	total := resp.Total
	offset := 0

	// Process first page
	if err := r.bulkInsert(ctx, resp.Data, date); err != nil {
		return err
	}
	offset += len(resp.Data)
	slog.Info("Ingested EPSS batch", "offset", offset, "total", total)

	for offset < total {
		url := fmt.Sprintf("%s?limit=%d&offset=%d", r.cfg.URL, pageSize, offset)

		pData, err := r.fetch(url)
		if err != nil {
			slog.Error("Failed to fetch EPSS page", "offset", offset, "error", err)
			break
		}

		if len(pData.Data) == 0 {
			break
		}

		if err := r.bulkInsert(ctx, pData.Data, date); err != nil {
			slog.Error("Failed to bulk insert EPSS", "error", err)
			return err
		}

		offset += len(pData.Data)
		slog.Info("Ingested EPSS batch", "offset", offset, "total", total)

		time.Sleep(100 * time.Millisecond) // Rate limit
	}

	slog.Info("EPSS ingestion complete", "date", dateStr, "total", total)
	return nil
}

func (r *EpssRunner) fetch(url string) (*EpssResponse, error) {
	resp, err := r.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var page EpssResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, err
	}
	return &page, nil
}

func (r *EpssRunner) ensurePartition(ctx context.Context, date time.Time) error {
	// Partition by month
	startOfMonth := time.Date(date.Year(), date.Month(), 1, 0, 0, 0, 0, time.UTC)
	nextMonth := startOfMonth.AddDate(0, 1, 0)

	partitionName := fmt.Sprintf("epss_daily_y%dm%02d", date.Year(), date.Month())

	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s 
		PARTITION OF epss_daily 
		FOR VALUES FROM ('%s') TO ('%s')
	`, partitionName, startOfMonth.Format("2006-01-02"), nextMonth.Format("2006-01-02"))

	_, err := r.db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create partition %s: %w", partitionName, err)
	}
	return nil
}

func (r *EpssRunner) bulkInsert(ctx context.Context, rows []EpssRow, date time.Time) error {
	// 1. Insert into epss_daily (History)
	inputRows := make([][]interface{}, len(rows))
	for i, row := range rows {
		inputRows[i] = []interface{}{
			row.CVE,
			row.EPSS,       // pgx will handle string -> numeric conversion if format is valid
			row.Percentile, // pgx will handle string -> numeric conversion if format is valid
			date,
			time.Now(), // inserted_at
		}
	}

	// Schema columns: as_of, cve_id, epss, percentile, raw (skipped), inserted_at
	copyCount, err := r.db.CopyFrom(
		ctx,
		pgx.Identifier{"epss_daily"},
		[]string{"cve_id", "epss", "percentile", "as_of", "inserted_at"},
		pgx.CopyFromRows(inputRows),
	)
	if err != nil {
		return fmt.Errorf("copy to epss_daily failed: %w", err)
	}
	_ = copyCount

	return nil
}
