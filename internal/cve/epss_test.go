package cve

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/db"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func utcDay(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// gzCSV builds an archive file the way FIRST ships it: a model comment,
// the header, then rows.
func gzCSV(scoreDate string, rows ...string) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = fmt.Fprintf(w, "#model_version:v2025.03.14,score_date:%sT00:00:00+0000\n", scoreDate)
	_, _ = fmt.Fprintln(w, "cve,epss,percentile")
	for _, r := range rows {
		_, _ = fmt.Fprintln(w, r)
	}
	_ = w.Close()
	return buf.Bytes()
}

func TestDaysToLoad(t *testing.T) {
	windowStart, today := utcDay("2026-10-01"), utcDay("2026-10-05")
	dates := func(ds []time.Time) []string {
		out := []string{}
		for _, d := range ds {
			out = append(out, d.Format("2006-01-02"))
		}
		return out
	}

	t.Run("missing and short days, oldest first", func(t *testing.T) {
		counts := map[time.Time]int{
			utcDay("2026-10-01"): 380000,
			utcDay("2026-10-02"): 247569, // the 28 September failure mode
			utcDay("2026-10-04"): 381000,
			// 2026-10-03 absent, 2026-10-05 (today) not yet published
		}
		assert.Equal(t, []string{"2026-10-02", "2026-10-03", "2026-10-05"}, dates(daysToLoad(counts, windowStart, today)))
	})

	t.Run("normal daily drift is not short", func(t *testing.T) {
		counts := map[time.Time]int{
			utcDay("2026-10-01"): 379842,
			utcDay("2026-10-02"): 380066,
			utcDay("2026-10-03"): 380526,
			utcDay("2026-10-04"): 381682,
			utcDay("2026-10-05"): 382205,
		}
		assert.Empty(t, daysToLoad(counts, windowStart, today))
	})

	t.Run("empty table loads the whole window", func(t *testing.T) {
		assert.Len(t, daysToLoad(map[time.Time]int{}, windowStart, today), 5)
	})
}

// numericText renders a pgtype.Numeric as <digits>e<exp>, the exact form
// it will be stored in.
func numericText(t *testing.T, v any) string {
	t.Helper()
	n, ok := v.(pgtype.Numeric)
	require.True(t, ok, "expected pgtype.Numeric, got %T", v)
	return fmt.Sprintf("%se%d", n.Int.String(), n.Exp)
}

func TestEpssCSVSource(t *testing.T) {
	t.Run("parses FIRST's layout", func(t *testing.T) {
		raw := "#model_version:v2025.03.14,score_date:2026-09-28T00:00:00+0000\n" +
			"cve,epss,percentile\n" +
			"CVE-1999-0001,0.01234,0.83421\n" +
			"\n" +
			"CVE-1999-0002,0.5,0.99\n"
		src, err := newEpssCSVSource(strings.NewReader(raw), utcDay("2026-09-28"), utcDay("2026-09-29"))
		require.NoError(t, err)

		var got [][]any
		for src.Next() {
			v, _ := src.Values()
			got = append(got, v)
		}
		require.NoError(t, src.Err())
		require.Len(t, got, 2)
		assert.Equal(t, "CVE-1999-0001", got[0][0])
		assert.Equal(t, "1234e-5", numericText(t, got[0][1]))
		assert.Equal(t, "83421e-5", numericText(t, got[0][2]))
		assert.Equal(t, utcDay("2026-09-28"), got[0][3])
		assert.Equal(t, utcDay("2026-09-29"), got[0][4])
		assert.Equal(t, "CVE-1999-0002", got[1][0])
	})

	t.Run("exact decimals, including the archive's scientific notation", func(t *testing.T) {
		for in, want := range map[string]string{
			"6e-05":   "6e-5",
			"0.03351": "3351e-5",
			"1":       "1e0",
			"0.5":     "5e-1",
			"1.0E+2":  "10e1",
			"-0.25":   "-25e-2",
		} {
			n, err := parseDecimal(in)
			require.NoError(t, err, in)
			assert.Equal(t, want, numericText(t, n), in)
		}
		for _, bad := range []string{"", "n/a", "1e", "0.1.2", "e5", ".", "1e99999999999"} {
			_, err := parseDecimal(bad)
			assert.Error(t, err, bad)
		}
	})

	t.Run("refuses a file for a different day", func(t *testing.T) {
		raw := "#model_version:v2025.03.14,score_date:2026-09-27T00:00:00+0000\ncve,epss,percentile\n"
		_, err := newEpssCSVSource(strings.NewReader(raw), utcDay("2026-09-28"), time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file is for 2026-09-27")
	})

	t.Run("refuses an unexpected header", func(t *testing.T) {
		_, err := newEpssCSVSource(strings.NewReader("id,score\n"), utcDay("2026-09-28"), time.Now())
		require.Error(t, err)
	})

	t.Run("no comment line is fine", func(t *testing.T) {
		src, err := newEpssCSVSource(strings.NewReader("cve,epss,percentile\nCVE-1,0.1,0.2\n"), utcDay("2026-09-28"), time.Now())
		require.NoError(t, err)
		assert.True(t, src.Next())
		assert.False(t, src.Next())
		assert.NoError(t, src.Err())
	})

	t.Run("bad number stops the stream with the line", func(t *testing.T) {
		src, err := newEpssCSVSource(strings.NewReader("cve,epss,percentile\nCVE-1,0.1,0.2\nCVE-2,n/a,0.3\n"), utcDay("2026-09-28"), time.Now())
		require.NoError(t, err)
		assert.True(t, src.Next())
		assert.False(t, src.Next())
		require.Error(t, src.Err())
		assert.Contains(t, src.Err().Error(), "line 3")
	})
}

// archive is a fake FIRST archive: files by date, 404 otherwise, and a
// log of what was asked for.
type archive struct {
	mu    sync.Mutex
	files map[string][]byte
	asked []string
}

func (a *archive) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /epss_scores-2100-01-07.csv.gz
		date := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/epss_scores-"), ".csv.gz")
		a.mu.Lock()
		a.asked = append(a.asked, date)
		body, ok := a.files[date]
		a.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}
}

func (a *archive) requested() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.asked...)
}

// TestEpssRunner_Integration requires a running DB. Everything it writes
// lives in January 2100 and is removed afterwards.
func TestEpssRunner_Integration(t *testing.T) {
	databaseURL, ok := os.LookupEnv("DATABASE_URL")
	if !ok || databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ctx := context.Background()
	require.NoError(t, db.Migrate(databaseURL, "../../migrations"))
	pool, err := db.NewPool(ctx, databaseURL)
	require.NoError(t, err)
	// Registered before the row cleanup so it runs after it (LIFO).
	t.Cleanup(pool.Close)

	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM epss_daily WHERE as_of >= '2100-01-01' AND as_of < '2100-02-01'")
	}
	cleanup()
	t.Cleanup(cleanup)

	count := func(day string) int {
		var n int
		require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM epss_daily WHERE as_of = $1", utcDay(day)).Scan(&n))
		return n
	}
	seed := func(day string, n int) {
		for i := 0; i < n; i++ {
			_, err := pool.Exec(ctx,
				"INSERT INTO epss_daily (cve_id, epss, percentile, as_of, inserted_at) VALUES ($1, 0.1, 0.5, $2, '2100-01-01')",
				fmt.Sprintf("CVE-SEED-%04d", i), utcDay(day))
			require.NoError(t, err)
		}
	}
	newRunner := func(a *archive, today string) *EpssRunner {
		srv := httptest.NewServer(a.handler())
		t.Cleanup(srv.Close)
		r := NewEpssRunner(pool, config.EpssConfig{
			Enabled:      true,
			ArchiveURL:   srv.URL + "/epss_scores-{date}.csv.gz",
			BackfillDays: 5,
		})
		r.now = func() time.Time { return utcDay(today).Add(13 * time.Hour) }
		return r
	}
	three := func(day string) []byte {
		return gzCSV(day, "CVE-2100-0001,0.1,0.5", "CVE-2100-0002,0.2,0.6", "CVE-2100-0003,6e-05,0.7")
	}

	// Window is 2100-01-06 .. 2100-01-10.
	t.Run("repairs a short day, backfills a missing one, waits for today", func(t *testing.T) {
		cleanup()
		require.NoError(t, NewEpssRunner(pool, config.EpssConfig{}).ensurePartition(ctx, utcDay("2100-01-06")))
		seed("2100-01-06", 3) // complete: the benchmark
		seed("2100-01-07", 1) // short

		a := &archive{files: map[string][]byte{
			"2100-01-07": three("2100-01-07"),
			"2100-01-08": three("2100-01-08"),
			// 01-09 missing from the archive, 01-10 (today) not published yet
		}}
		require.NoError(t, newRunner(a, "2100-01-10").Run(ctx))

		assert.Equal(t, 3, count("2100-01-06"))
		assert.Equal(t, 3, count("2100-01-07"), "short day replaced whole")
		assert.Equal(t, 3, count("2100-01-08"), "missing day backfilled")
		assert.Equal(t, 0, count("2100-01-09"))
		assert.Equal(t, 0, count("2100-01-10"))
		assert.Equal(t, []string{"2100-01-07", "2100-01-08", "2100-01-09", "2100-01-10"}, a.requested(),
			"complete days are never fetched")

		var seeded int
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT count(*) FROM epss_daily WHERE as_of = '2100-01-07' AND cve_id LIKE 'CVE-SEED-' || '%'").Scan(&seeded))
		assert.Equal(t, 0, seeded, "the partial rows are gone, not merged")

		var tiny string
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT epss::text FROM epss_daily WHERE as_of = '2100-01-08' AND cve_id = 'CVE-2100-0003'").Scan(&tiny))
		assert.Equal(t, "0.00006", tiny, "scientific notation stored as an exact decimal")

		// Second run: nothing to do but ask for the two absent days again.
		require.NoError(t, newRunner(a, "2100-01-10").Run(ctx))
		assert.Equal(t, 3, count("2100-01-07"))
	})

	t.Run("keeps the lake's copy when the archive is shorter", func(t *testing.T) {
		cleanup()
		seed("2100-01-06", 10)
		seed("2100-01-07", 5) // short against 10

		a := &archive{files: map[string][]byte{
			"2100-01-07": three("2100-01-07"),
		}}
		err := newRunner(a, "2100-01-07").Run(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already had 5")
		assert.Equal(t, 5, count("2100-01-07"))
	})

	t.Run("a file for the wrong day is refused and the day stays empty", func(t *testing.T) {
		cleanup()
		seed("2100-01-06", 3)

		a := &archive{files: map[string][]byte{
			"2100-01-07": three("2100-01-06"), // mislabelled
		}}
		err := newRunner(a, "2100-01-07").Run(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file is for 2100-01-06")
		assert.Equal(t, 0, count("2100-01-07"))
	})
}
