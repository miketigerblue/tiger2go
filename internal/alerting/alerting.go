package alerting

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SleeperCVE represents a CVE that crossed a significant EPSS threshold.
type SleeperCVE struct {
	CVEID        string
	EpssBefore   float64
	EpssNow      float64
	Delta        float64
	PctChange    float64
	Percentile   float64
	DateBefore   string
	DateNow      string
	Description  string
	CvssScore    *float64
	CvssSeverity string
	CWE          string
}

// Runner detects sleeper CVEs and sends webhook notifications.
type Runner struct {
	db       *pgxpool.Pool
	cfg      config.AlertingConfig
	webhooks []WebhookSender
}

// NewRunner creates a new alerting runner.
func NewRunner(db *pgxpool.Pool, cfg config.AlertingConfig) *Runner {
	senders := make([]WebhookSender, 0, len(cfg.Webhooks))
	for _, wh := range cfg.Webhooks {
		senders = append(senders, NewWebhookSender(wh))
	}
	return &Runner{db: db, cfg: cfg, webhooks: senders}
}

// Run executes one detection cycle: find sleeper CVEs and notify.
func (r *Runner) Run(ctx context.Context) error {
	start := time.Now()
	defer func() {
		metrics.AlertingRunDuration.Observe(time.Since(start).Seconds())
	}()

	lookback := r.cfg.LookbackDays
	if lookback <= 0 {
		lookback = 7
	}

	sleepers, err := r.detect(ctx, lookback)
	if err != nil {
		metrics.AlertingRuns.WithLabelValues("error").Inc()
		return fmt.Errorf("sleeper detection failed: %w", err)
	}

	if len(sleepers) == 0 {
		slog.Info("Alerting: no sleeper CVEs detected")
		metrics.AlertingRuns.WithLabelValues("none").Inc()
		return nil
	}

	slog.Info("Alerting: sleeper CVEs detected", "count", len(sleepers))
	metrics.AlertingSleeperCVEs.Add(float64(len(sleepers)))

	// Check cursor to avoid re-alerting
	var lastAlerted string
	err = r.db.QueryRow(ctx,
		"SELECT cursor FROM ingest_state WHERE source = 'ALERTING'",
	).Scan(&lastAlerted)
	if err != nil {
		lastAlerted = "" // first run
	}

	// Use the "now" date from the first sleeper as the cursor
	currentDate := sleepers[0].DateNow
	if currentDate == lastAlerted {
		slog.Info("Alerting: already alerted for this date, skipping", "date", currentDate)
		metrics.AlertingRuns.WithLabelValues("skipped").Inc()
		return nil
	}

	// Send to all configured webhooks
	for _, wh := range r.webhooks {
		if err := wh.Send(ctx, sleepers); err != nil {
			slog.Error("Alerting: webhook delivery failed", "webhook", wh.Name(), "error", err)
			metrics.AlertingWebhooksSent.WithLabelValues(wh.Name(), "error").Inc()
		} else {
			slog.Info("Alerting: webhook delivered", "webhook", wh.Name(), "sleepers", len(sleepers))
			metrics.AlertingWebhooksSent.WithLabelValues(wh.Name(), "success").Inc()
		}
	}

	// Update cursor so we don't re-alert
	_, err = r.db.Exec(ctx, `
		INSERT INTO ingest_state (source, cursor) VALUES ('ALERTING', $1)
		ON CONFLICT (source) DO UPDATE SET cursor = EXCLUDED.cursor
	`, currentDate)
	if err != nil {
		slog.Error("Alerting: failed to update cursor", "error", err)
	}

	metrics.AlertingRuns.WithLabelValues("success").Inc()
	return nil
}

// detect queries epss_daily for CVEs that crossed the 50% threshold
// compared to `lookback` days ago, starting from below 10%.
func (r *Runner) detect(ctx context.Context, lookbackDays int) ([]SleeperCVE, error) {
	query := `
		WITH latest_date AS (
			SELECT max(as_of) AS d FROM epss_daily
		),
		baseline_date AS (
			SELECT max(as_of) AS d FROM epss_daily
			WHERE as_of <= (SELECT d FROM latest_date) - $1::int
		),
		now_scores AS (
			SELECT cve_id, epss::float8 AS epss, percentile::float8 AS pct
			FROM epss_daily
			WHERE as_of = (SELECT d FROM latest_date)
		),
		before_scores AS (
			SELECT cve_id, epss::float8 AS epss
			FROM epss_daily
			WHERE as_of = (SELECT d FROM baseline_date)
		)
		SELECT
			n.cve_id,
			b.epss AS epss_before,
			n.epss AS epss_now,
			n.epss - b.epss AS delta,
			CASE WHEN b.epss > 0 THEN ((n.epss - b.epss) / b.epss) * 100 ELSE 0 END AS pct_change,
			n.pct AS percentile,
			(SELECT d FROM baseline_date)::text AS date_before,
			(SELECT d FROM latest_date)::text AS date_now,
			COALESCE(
				(SELECT json->'descriptions'->0->>'value'
				 FROM cve_enriched WHERE cve_id = n.cve_id LIMIT 1),
				''
			) AS description,
			(SELECT cvss_base::float8
			 FROM cve_enriched WHERE cve_id = n.cve_id LIMIT 1
			) AS cvss_score,
			COALESCE(
				(SELECT json->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseSeverity'
				 FROM cve_enriched WHERE cve_id = n.cve_id LIMIT 1),
				''
			) AS cvss_severity,
			COALESCE(
				(SELECT json->'weaknesses'->0->'description'->0->>'value'
				 FROM cve_enriched WHERE cve_id = n.cve_id LIMIT 1),
				''
			) AS cwe
		FROM now_scores n
		JOIN before_scores b ON n.cve_id = b.cve_id
		WHERE b.epss < 0.10
		  AND n.epss >= 0.50
		ORDER BY n.epss - b.epss DESC
		LIMIT 50
	`

	rows, err := r.db.Query(ctx, query, lookbackDays)
	if err != nil {
		return nil, fmt.Errorf("sleeper query failed: %w", err)
	}
	defer rows.Close()

	var sleepers []SleeperCVE
	for rows.Next() {
		var s SleeperCVE
		if err := rows.Scan(
			&s.CVEID, &s.EpssBefore, &s.EpssNow, &s.Delta,
			&s.PctChange, &s.Percentile,
			&s.DateBefore, &s.DateNow, &s.Description,
			&s.CvssScore, &s.CvssSeverity, &s.CWE,
		); err != nil {
			return nil, fmt.Errorf("scan sleeper row: %w", err)
		}
		sleepers = append(sleepers, s)
	}
	return sleepers, rows.Err()
}
