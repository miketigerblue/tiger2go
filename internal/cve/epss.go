package cve

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultEpssArchiveURL is FIRST's daily archive: one gzipped CSV per
// score date, back to 2021. One file per day is what makes a day
// all-or-nothing; the paginated API this replaced left 28 September 2026
// at 247,569 of ~380,000 rows when a run died mid-way, and the
// date-exists check meant it could never be completed.
const defaultEpssArchiveURL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"

// defaultEpssBackfillDays is how far back each run looks for missing or
// short days.
const defaultEpssBackfillDays = 14

// epssShortDayRatio: a day holding fewer rows than this share of the
// largest day in the window is treated as a failed load and reloaded.
// Day-to-day the population moves by well under 1%.
const epssShortDayRatio = 0.95

// errEpssNotPublished is returned when the archive has no file for a
// date yet: normal for today until FIRST publishes.
var errEpssNotPublished = errors.New("epss: archive has no file for that date")

// EpssRunner handles EPSS data ingestion.
type EpssRunner struct {
	db     *pgxpool.Pool
	cfg    config.EpssConfig
	client *http.Client
	now    func() time.Time
}

// NewEpssRunner creates a new instance of EpssRunner.
func NewEpssRunner(db *pgxpool.Pool, cfg config.EpssConfig) *EpssRunner {
	return &EpssRunner{
		db:  db,
		cfg: cfg,
		client: &http.Client{
			Timeout: 5 * time.Minute, // one ~7 MB file per day
		},
		now: time.Now,
	}
}

// Run brings the last backfill_days of epss_daily up to date: any day in
// the window that is missing, or short against the others, is loaded
// whole from the archive. Today's file simply is not there until FIRST
// publishes it, and is picked up by a later run. Days are independent:
// one failing does not stop the rest.
func (r *EpssRunner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("EPSS ingestion disabled")
		return nil
	}

	start := time.Now()
	defer func() {
		metrics.EpssRunDuration.Observe(time.Since(start).Seconds())
		if retErr != nil {
			metrics.EpssRuns.WithLabelValues("error").Inc()
		} else {
			metrics.EpssRuns.WithLabelValues("success").Inc()
		}
	}()

	days := r.cfg.BackfillDays
	if days <= 0 {
		days = defaultEpssBackfillDays
	}
	today := r.now().UTC().Truncate(24 * time.Hour)
	windowStart := today.AddDate(0, 0, -(days - 1))

	counts, err := r.dayCounts(ctx, windowStart)
	if err != nil {
		return fmt.Errorf("failed to count EPSS days: %w", err)
	}

	var errs []error
	for _, d := range daysToLoad(counts, windowStart, today) {
		have := counts[d]
		loaded, err := r.loadDay(ctx, d, have)
		switch {
		case errors.Is(err, errEpssNotPublished):
			if d.Equal(today) {
				slog.Info("EPSS snapshot not published yet", "date", d.Format("2006-01-02"))
			} else {
				slog.Warn("EPSS archive has no file for a past date", "date", d.Format("2006-01-02"))
			}
		case err != nil:
			slog.Error("EPSS day load failed", "date", d.Format("2006-01-02"), "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", d.Format("2006-01-02"), err))
		default:
			reason := "new"
			if have > 0 {
				reason = "repair"
			} else if d.Before(today) {
				reason = "backfill"
			}
			metrics.EpssDaysLoaded.WithLabelValues(reason).Inc()
			metrics.EpssRecordsProcessed.Add(float64(loaded))
			slog.Info("EPSS day loaded", "date", d.Format("2006-01-02"), "rows", loaded, "replaced", have, "reason", reason)
			counts[d] = loaded
		}
	}

	var newest time.Time
	for d, n := range counts {
		if n > 0 && d.After(newest) {
			newest = d
		}
	}
	if !newest.IsZero() {
		metrics.EpssCursorLag.Set(r.now().UTC().Sub(newest).Seconds())
	}

	return errors.Join(errs...)
}

// dayCounts returns rows per as_of from windowStart on.
func (r *EpssRunner) dayCounts(ctx context.Context, windowStart time.Time) (map[time.Time]int, error) {
	rows, err := r.db.Query(ctx,
		"SELECT as_of, count(*) FROM epss_daily WHERE as_of >= $1 GROUP BY as_of", windowStart)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[time.Time]int{}
	for rows.Next() {
		var d time.Time
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			return nil, err
		}
		counts[d.UTC().Truncate(24*time.Hour)] = n
	}
	return counts, rows.Err()
}

// daysToLoad picks the days in [windowStart, today] that are absent or
// short against the fullest day in the window, oldest first. A fresh
// table has no benchmark, so every day in the window is loaded.
func daysToLoad(counts map[time.Time]int, windowStart, today time.Time) []time.Time {
	benchmark := 0
	for _, n := range counts {
		if n > benchmark {
			benchmark = n
		}
	}
	floor := int(float64(benchmark) * epssShortDayRatio)

	var out []time.Time
	for d := windowStart; !d.After(today); d = d.AddDate(0, 0, 1) {
		if n := counts[d]; n == 0 || n < floor {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

// loadDay replaces whatever epss_daily holds for date with the archive
// file for that date, in one transaction, and returns the rows written.
// It refuses to leave the day with fewer rows than it had.
func (r *EpssRunner) loadDay(ctx context.Context, date time.Time, have int) (int, error) {
	body, err := r.fetchArchive(ctx, date)
	if err != nil {
		return 0, err
	}
	defer func() { _ = body.Close() }()

	gz, err := gzip.NewReader(body)
	if err != nil {
		return 0, fmt.Errorf("gunzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	src, err := newEpssCSVSource(gz, date, time.Now())
	if err != nil {
		return 0, err
	}

	if err := r.ensurePartition(ctx, date); err != nil {
		return 0, err
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if have > 0 {
		if _, err := tx.Exec(ctx, "DELETE FROM epss_daily WHERE as_of = $1", date); err != nil {
			return 0, fmt.Errorf("clear partial day: %w", err)
		}
	}

	n, err := tx.CopyFrom(ctx,
		pgx.Identifier{"epss_daily"},
		[]string{"cve_id", "epss", "percentile", "as_of", "inserted_at"},
		src)
	if err != nil {
		return 0, fmt.Errorf("copy to epss_daily failed: %w", err)
	}
	if int(n) < have {
		return 0, fmt.Errorf("archive holds %d rows but the lake already had %d; keeping the lake's copy", n, have)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int(n), nil
}

func (r *EpssRunner) fetchArchive(ctx context.Context, date time.Time) (io.ReadCloser, error) {
	tmpl := r.cfg.ArchiveURL
	if tmpl == "" {
		tmpl = defaultEpssArchiveURL
	}
	url := strings.ReplaceAll(tmpl, "{date}", date.Format("2006-01-02"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tigerfetch/1.0 (+https://tigerblue.app)")

	httpStart := time.Now()
	resp, err := r.client.Do(req)
	metrics.UpstreamRequestDuration.WithLabelValues("epss").Observe(time.Since(httpStart).Seconds())
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp.Body, nil
	case http.StatusNotFound:
		_ = resp.Body.Close()
		return nil, errEpssNotPublished
	default:
		_ = resp.Body.Close()
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
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

// epssCSVSource streams an archive file into COPY. The file is
//
//	#model_version:v2025.03.14,score_date:2026-09-28T00:00:00+0000
//	cve,epss,percentile
//	CVE-1999-0001,0.01234,0.83421
//
// The comment's score_date is checked against the requested date so a
// redirect to a different day can never be stored under the wrong one.
type epssCSVSource struct {
	r          *csv.Reader
	asOf       time.Time
	insertedAt time.Time
	line       int
	cur        []any
	err        error
}

func newEpssCSVSource(raw io.Reader, asOf time.Time, insertedAt time.Time) (*epssCSVSource, error) {
	r := csv.NewReader(raw)
	r.Comment = 0 // handled below so score_date can be read
	r.FieldsPerRecord = -1

	s := &epssCSVSource{r: r, asOf: asOf, insertedAt: insertedAt}

	// Leading comment lines, then the header.
	for {
		rec, err := r.Read()
		if err != nil {
			return nil, fmt.Errorf("epss csv header: %w", err)
		}
		s.line++
		if len(rec) > 0 && strings.HasPrefix(rec[0], "#") {
			if err := checkScoreDate(strings.Join(rec, ","), asOf); err != nil {
				return nil, err
			}
			continue
		}
		if len(rec) < 3 || !strings.EqualFold(rec[0], "cve") || !strings.EqualFold(rec[1], "epss") || !strings.EqualFold(rec[2], "percentile") {
			return nil, fmt.Errorf("epss csv: unexpected header %q", rec)
		}
		return s, nil
	}
}

// checkScoreDate parses "score_date:2026-09-28T00:00:00+0000" out of the
// comment line when present and compares the date part.
func checkScoreDate(comment string, asOf time.Time) error {
	i := strings.Index(comment, "score_date:")
	if i < 0 {
		return nil
	}
	got := comment[i+len("score_date:"):]
	if len(got) < 10 {
		return fmt.Errorf("epss csv: unreadable score_date in %q", comment)
	}
	if got[:10] != asOf.Format("2006-01-02") {
		return fmt.Errorf("epss csv: file is for %s, wanted %s", got[:10], asOf.Format("2006-01-02"))
	}
	return nil
}

func (s *epssCSVSource) Next() bool {
	for {
		rec, err := s.r.Read()
		if err == io.EOF {
			return false
		}
		if err != nil {
			s.err = fmt.Errorf("epss csv line %d: %w", s.line+1, err)
			return false
		}
		s.line++
		if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
			continue
		}
		if len(rec) < 3 {
			s.err = fmt.Errorf("epss csv line %d: expected 3 fields, got %d", s.line, len(rec))
			return false
		}
		epss, err := parseDecimal(rec[1])
		if err != nil {
			s.err = fmt.Errorf("epss csv line %d: %w", s.line, err)
			return false
		}
		percentile, err := parseDecimal(rec[2])
		if err != nil {
			s.err = fmt.Errorf("epss csv line %d: %w", s.line, err)
			return false
		}
		s.cur = []any{rec[0], epss, percentile, s.asOf, s.insertedAt}
		return true
	}
}

func (s *epssCSVSource) Values() ([]any, error) { return s.cur, nil }
func (s *epssCSVSource) Err() error             { return s.err }

// parseDecimal turns a CSV number into an exact numeric. The archive
// prints small scores in scientific notation ("6e-05"), which pgx's
// text-to-numeric path rejects, and a float64 round-trip would not be
// exact for the rest. Digits and a base-10 exponent are what numeric
// stores anyway.
func parseDecimal(s string) (pgtype.Numeric, error) {
	mant, exp := s, 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return pgtype.Numeric{}, fmt.Errorf("bad number %q", s)
		}
		mant, exp = s[:i], e
	}
	neg := strings.HasPrefix(mant, "-")
	mant = strings.TrimPrefix(strings.TrimPrefix(mant, "-"), "+")

	intPart, fracPart := mant, ""
	if i := strings.IndexByte(mant, '.'); i >= 0 {
		intPart, fracPart = mant[:i], mant[i+1:]
	}
	digits := intPart + fracPart
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return pgtype.Numeric{}, fmt.Errorf("bad number %q", s)
	}
	n, _ := new(big.Int).SetString(digits, 10)
	if neg {
		n.Neg(n)
	}
	scale := exp - len(fracPart)
	if scale < -1000 || scale > 1000 {
		return pgtype.Numeric{}, fmt.Errorf("bad number %q", s)
	}
	return pgtype.Numeric{Int: n, Exp: int32(scale), Valid: true}, nil
}
