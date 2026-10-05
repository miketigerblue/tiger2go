// Package maintenance holds housekeeping tasks that bound the lake's
// footprint. They delete data, so the worker is off unless enabled.
package maintenance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// minEpssRetentionDays is the smallest retention Run will act on. The
// sleeper alert reads a full snapshot lookback_days (default 7) back;
// twice that leaves room, and it rejects a mistyped "9" for "90".
const minEpssRetentionDays = 14

// upperBoundRe extracts the exclusive upper bound from a range partition's
// bound expression: FOR VALUES FROM ('2026-03-01') TO ('2026-04-01').
var upperBoundRe = regexp.MustCompile(`TO \('(\d{4}-\d{2}-\d{2})'\)$`)

type partition struct {
	name  string    // regclass text: schema-qualified and quoted as needed
	upper time.Time // exclusive upper bound
}

// Runner enforces retention on the monthly epss_daily partitions.
type Runner struct {
	db          *pgxpool.Pool
	cfg         config.MaintenanceConfig
	table       string
	lockTimeout time.Duration
}

// NewRunner creates a new instance of Runner.
func NewRunner(db *pgxpool.Pool, cfg config.MaintenanceConfig) *Runner {
	return &Runner{
		db:    db,
		cfg:   cfg,
		table: "epss_daily",
		// DROP needs ACCESS EXCLUSIVE on the parent, and every other query
		// queues behind a waiting DROP. Give up quickly rather than stall
		// all epss_daily readers behind one long query; the next run retries.
		lockTimeout: 5 * time.Second,
	}
}

// Run drops every partition whose rows are all older than the retention
// window. Rows are never deleted individually, so the partition straddling
// the cutoff is kept whole: retention is "at least N days", up to a month more.
func (r *Runner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("Maintenance disabled")
		return nil
	}

	days := r.cfg.EpssRetentionDays
	if days <= 0 {
		slog.Info("EPSS retention not configured, skipping")
		return nil
	}

	defer func() {
		if retErr != nil {
			metrics.MaintenanceRuns.WithLabelValues("error").Inc()
		} else {
			metrics.MaintenanceRuns.WithLabelValues("success").Inc()
		}
	}()

	if days < minEpssRetentionDays {
		return fmt.Errorf("epss_retention_days=%d is below the minimum of %d, refusing to prune", days, minEpssRetentionDays)
	}

	// Anchor on the newest snapshot, not the wall clock, so a stalled ingest
	// never lets retention eat the history that is left. Capped at today in
	// case a future-dated row ever lands. Not LEAST(): it skips NULLs, which
	// would turn an empty table back into a wall-clock anchor.
	var newest *time.Time
	var today time.Time
	err := r.db.QueryRow(ctx,
		"SELECT max(as_of), (now() AT TIME ZONE 'utc')::date FROM "+pgx.Identifier{r.table}.Sanitize(),
	).Scan(&newest, &today)
	if err != nil {
		return fmt.Errorf("failed to read newest EPSS snapshot date: %w", err)
	}
	if newest == nil {
		slog.Info("No EPSS snapshots, nothing to prune")
		return nil
	}
	anchor := *newest
	if anchor.After(today) {
		anchor = today
	}
	cutoff := anchor.AddDate(0, 0, -days)

	parts, err := r.partitions(ctx)
	if err != nil {
		return fmt.Errorf("failed to list %s partitions: %w", r.table, err)
	}

	var errs []error
	for _, p := range expired(parts, cutoff) {
		if err := r.drop(ctx, p); err != nil {
			slog.Error("Failed to drop expired partition", "partition", p.name, "error", err)
			errs = append(errs, fmt.Errorf("drop %s: %w", p.name, err))
			continue
		}
		metrics.MaintenancePartitionsDropped.WithLabelValues(r.table).Inc()
		slog.Info("Dropped expired partition",
			"partition", p.name,
			"upper_bound", p.upper.Format("2006-01-02"),
			"cutoff", cutoff.Format("2006-01-02"))
	}
	return errors.Join(errs...)
}

// partitions lists the table's range partitions. A DEFAULT partition, or
// any bound this code does not understand, is left out: never a candidate.
func (r *Runner) partitions(ctx context.Context) ([]partition, error) {
	rows, err := r.db.Query(ctx, `
		SELECT c.oid::regclass::text, COALESCE(pg_get_expr(c.relpartbound, c.oid), '')
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = to_regclass($1)
		ORDER BY c.relname`, r.table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var parts []partition
	for rows.Next() {
		var name, bound string
		if err := rows.Scan(&name, &bound); err != nil {
			return nil, err
		}
		upper, ok := parseUpperBound(bound)
		if !ok {
			continue
		}
		parts = append(parts, partition{name: name, upper: upper})
	}
	return parts, rows.Err()
}

func (r *Runner) drop(ctx context.Context, p partition) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	timeout := fmt.Sprintf("%dms", r.lockTimeout.Milliseconds())
	if _, err := tx.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", timeout); err != nil {
		return err
	}
	// p.name is regclass output from the catalog, so already quoted. No
	// CASCADE: if something has come to depend on the partition, fail.
	if _, err := tx.Exec(ctx, "DROP TABLE "+p.name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// expired returns the partitions that hold nothing on or after cutoff.
func expired(parts []partition, cutoff time.Time) []partition {
	var out []partition
	for _, p := range parts {
		if !p.upper.After(cutoff) {
			out = append(out, p)
		}
	}
	return out
}

func parseUpperBound(bound string) (time.Time, bool) {
	m := upperBoundRe.FindStringSubmatch(bound)
	if m == nil {
		return time.Time{}, false
	}
	upper, err := time.Parse("2006-01-02", m[1])
	if err != nil {
		return time.Time{}, false
	}
	return upper, true
}
