package maintenance

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseUpperBound(t *testing.T) {
	tests := []struct {
		name   string
		bound  string
		want   time.Time
		wantOK bool
	}{
		{"monthly range", "FOR VALUES FROM ('2026-03-01') TO ('2026-04-01')", day("2026-04-01"), true},
		{"default partition", "DEFAULT", time.Time{}, false},
		{"timestamp bound", "FOR VALUES FROM ('2026-03-01 00:00:00') TO ('2026-04-01 00:00:00')", time.Time{}, false},
		{"unbounded above", "FOR VALUES FROM ('2026-03-01') TO (MAXVALUE)", time.Time{}, false},
		{"list partition", "FOR VALUES IN ('2026-04-01')", time.Time{}, false},
		{"impossible date", "FOR VALUES FROM ('2026-03-01') TO ('2026-13-01')", time.Time{}, false},
		{"empty", "", time.Time{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseUpperBound(tt.bound)
			assert.Equal(t, tt.wantOK, ok)
			assert.True(t, tt.want.Equal(got))
		})
	}
}

func TestExpired(t *testing.T) {
	parts := []partition{
		{name: "epss_daily_y2026m06", upper: day("2026-07-01")},
		{name: "epss_daily_y2026m07", upper: day("2026-08-01")},
		{name: "epss_daily_y2026m08", upper: day("2026-09-01")},
	}
	names := func(ps []partition) []string {
		out := []string{}
		for _, p := range ps {
			out = append(out, p.name)
		}
		return out
	}

	// 2026-10-04 minus 90 days: July still holds days inside the window.
	assert.Equal(t, []string{"epss_daily_y2026m06"}, names(expired(parts, day("2026-07-06"))))
	// One day short of July's upper bound: 2026-07-31 is still wanted.
	assert.Equal(t, []string{"epss_daily_y2026m06"}, names(expired(parts, day("2026-07-31"))))
	// Cutoff on the bound itself: nothing in July is on or after it.
	assert.Equal(t, []string{"epss_daily_y2026m06", "epss_daily_y2026m07"}, names(expired(parts, day("2026-08-01"))))
	assert.Empty(t, expired(parts, day("2026-06-30")))
}

// A nil pool proves these return before touching the database.
func TestRun_NoRetentionConfigured(t *testing.T) {
	r := NewRunner(nil, config.MaintenanceConfig{Enabled: true})
	assert.NoError(t, r.Run(context.Background()))

	r = NewRunner(nil, config.MaintenanceConfig{EpssRetentionDays: 90})
	assert.NoError(t, r.Run(context.Background()))
}

func TestRun_RefusesRetentionBelowMinimum(t *testing.T) {
	r := NewRunner(nil, config.MaintenanceConfig{Enabled: true, EpssRetentionDays: 9})
	err := r.Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below the minimum")
}

func monthStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// createPartitioned builds a scratch table shaped like epss_daily with one
// monthly partition per entry in months, and returns the partition names.
// The tests never run against epss_daily itself: Run drops tables.
func createPartitioned(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string, months ...time.Time) []string {
	t.Helper()
	parent := pgx.Identifier{table}.Sanitize()

	_, err := pool.Exec(ctx, "DROP TABLE IF EXISTS "+parent)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "CREATE TABLE "+parent+" (as_of date NOT NULL, cve_id text NOT NULL) PARTITION BY RANGE (as_of)")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+parent) })

	names := make([]string, 0, len(months))
	for _, m := range months {
		start := monthStart(m)
		name := fmt.Sprintf("%s_y%dm%02d", table, start.Year(), start.Month())
		_, err := pool.Exec(ctx, fmt.Sprintf(
			"CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
			pgx.Identifier{name}.Sanitize(), parent,
			start.Format("2006-01-02"), start.AddDate(0, 1, 0).Format("2006-01-02"),
		))
		require.NoError(t, err)
		names = append(names, name)
	}
	return names
}

func insertSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string, asOf time.Time) {
	t.Helper()
	_, err := pool.Exec(ctx, "INSERT INTO "+pgx.Identifier{table}.Sanitize()+" (as_of, cve_id) VALUES ($1, 'CVE-TEST-0001')", asOf)
	require.NoError(t, err)
}

func remainingPartitions(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT c.relname FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = to_regclass($1)
		ORDER BY c.relname`, table)
	require.NoError(t, err)
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return names
}

// TestRunner_Integration requires a running DB. It only ever creates and
// drops its own maintenance_test_* tables.
func TestRunner_Integration(t *testing.T) {
	databaseURL, ok := os.LookupEnv("DATABASE_URL")
	if !ok || databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ctx := context.Background()
	pool, err := db.NewPool(ctx, databaseURL)
	require.NoError(t, err)
	// Registered before the table cleanups so it runs after them (LIFO).
	t.Cleanup(pool.Close)

	cfg := config.MaintenanceConfig{Enabled: true, EpssRetentionDays: 90}
	today := time.Now().UTC().Truncate(24 * time.Hour)

	t.Run("drops only partitions wholly past the cutoff", func(t *testing.T) {
		const table = "maintenance_test_window"
		old := monthStart(today).AddDate(0, -6, 0)
		straddling := today.AddDate(0, 0, -90)
		future := day("2100-01-01")
		parts := createPartitioned(t, ctx, pool, table, old, straddling, today, future)
		_, err := pool.Exec(ctx, "CREATE TABLE maintenance_test_window_default PARTITION OF "+table+" DEFAULT")
		require.NoError(t, err)

		insertSnapshot(t, ctx, pool, table, old)
		insertSnapshot(t, ctx, pool, table, straddling)
		insertSnapshot(t, ctx, pool, table, today)
		// A future-dated row must not drag the cutoff forward with it.
		insertSnapshot(t, ctx, pool, table, future)

		r := NewRunner(pool, cfg)
		r.table = table
		require.NoError(t, r.Run(ctx))

		assert.ElementsMatch(t,
			[]string{parts[1], parts[2], parts[3], "maintenance_test_window_default"},
			remainingPartitions(t, ctx, pool, table))

		// Nothing left to do on the next cycle.
		require.NoError(t, r.Run(ctx))
		assert.Len(t, remainingPartitions(t, ctx, pool, table), 4)
	})

	t.Run("anchors on the newest snapshot when ingest has stalled", func(t *testing.T) {
		const table = "maintenance_test_stalled"
		newest := today.AddDate(0, 0, -300)
		old := monthStart(newest).AddDate(0, -6, 0)
		straddling := newest.AddDate(0, 0, -90)
		parts := createPartitioned(t, ctx, pool, table, old, straddling, newest)
		insertSnapshot(t, ctx, pool, table, old)
		insertSnapshot(t, ctx, pool, table, straddling)
		insertSnapshot(t, ctx, pool, table, newest)

		r := NewRunner(pool, cfg)
		r.table = table
		require.NoError(t, r.Run(ctx))

		// By the wall clock all three are over 90 days old. Only the one
		// that is 90 days behind the last snapshot we actually hold goes.
		assert.ElementsMatch(t, []string{parts[1], parts[2]}, remainingPartitions(t, ctx, pool, table))
	})

	t.Run("empty table is left alone", func(t *testing.T) {
		const table = "maintenance_test_empty"
		parts := createPartitioned(t, ctx, pool, table, monthStart(today).AddDate(0, -6, 0))

		r := NewRunner(pool, cfg)
		r.table = table
		require.NoError(t, r.Run(ctx))

		assert.Equal(t, parts, remainingPartitions(t, ctx, pool, table))
	})

	t.Run("gives up instead of queueing behind a long reader", func(t *testing.T) {
		const table = "maintenance_test_locked"
		old := monthStart(today).AddDate(0, -6, 0)
		parts := createPartitioned(t, ctx, pool, table, old, today)
		insertSnapshot(t, ctx, pool, table, old)
		insertSnapshot(t, ctx, pool, table, today)

		reader, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = reader.Rollback(ctx) }()
		_, err = reader.Exec(ctx, "SELECT count(*) FROM "+table)
		require.NoError(t, err)

		r := NewRunner(pool, cfg)
		r.table = table
		r.lockTimeout = 200 * time.Millisecond

		start := time.Now()
		err = r.Run(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "lock timeout")
		assert.Less(t, time.Since(start), 3*time.Second)
		assert.Equal(t, parts, remainingPartitions(t, ctx, pool, table))

		// Once the reader is gone the next cycle finishes the job.
		require.NoError(t, reader.Rollback(ctx))
		require.NoError(t, r.Run(ctx))
		assert.Equal(t, []string{parts[1]}, remainingPartitions(t, ctx, pool, table))
	})
}
