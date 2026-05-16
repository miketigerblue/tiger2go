// Package abusech ingests the public abuse.ch threat-intel feeds.
//
// v1 ships URLhaus only because it's the one still available without an
// API key. ThreatFox and MalwareBazaar moved to auth-required in 2024 and
// will land as follow-ups once a key is configured (the package layout is
// already prepared for that — see SOURCES-TIERED.md).
//
// URLhaus source: https://urlhaus.abuse.ch/downloads/csv_recent/
// Schema: id, dateadded, url, url_status, last_online, threat, tags,
// urlhaus_link, reporter  (CSV with comment lines starting with `#`)
package abusech

import (
	"bufio"
	"context"
	"encoding/csv"
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

const defaultUrlhausURL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

// UrlhausRow mirrors one CSV row.
type UrlhausRow struct {
	ID          string
	DateAdded   string
	URL         string
	URLStatus   string
	LastOnline  string
	Threat      string
	Tags        string // comma-separated in the source
	UrlhausLink string
	Reporter    string
}

type UrlhausRunner struct {
	db     *pgxpool.Pool
	cfg    config.UrlhausConfig
	client *http.Client
}

func NewUrlhausRunner(db *pgxpool.Pool, cfg config.UrlhausConfig) *UrlhausRunner {
	return &UrlhausRunner{
		db:  db,
		cfg: cfg,
		client: &http.Client{
			Timeout: 120 * time.Second, // CSV can be a few MB
		},
	}
}

func (r *UrlhausRunner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("URLhaus ingestion disabled")
		return nil
	}

	start := time.Now()
	defer func() {
		metrics.UrlhausRunDuration.Observe(time.Since(start).Seconds())
		if retErr != nil {
			metrics.UrlhausFetches.WithLabelValues("error").Inc()
		} else {
			metrics.UrlhausFetches.WithLabelValues("success").Inc()
		}
	}()

	url := r.cfg.URL
	if url == "" {
		url = defaultUrlhausURL
	}

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

	processed, err := r.ingestCSV(ctx, resp.Body)
	if err != nil {
		return err
	}
	metrics.UrlhausRowsProcessed.Add(float64(processed))
	slog.Info("URLhaus ingestion complete", "rows", processed)
	return nil
}

func (r *UrlhausRunner) ingestCSV(ctx context.Context, body io.Reader) (int, error) {
	const upsertSQL = `
		INSERT INTO urlhaus_urls (
			id, url, url_status, threat, tags, date_added, last_online,
			urlhaus_link, reporter, raw, last_seen_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, now()
		)
		ON CONFLICT (id) DO UPDATE SET
			url           = EXCLUDED.url,
			url_status    = EXCLUDED.url_status,
			threat        = EXCLUDED.threat,
			tags          = EXCLUDED.tags,
			date_added    = EXCLUDED.date_added,
			last_online   = EXCLUDED.last_online,
			urlhaus_link  = EXCLUDED.urlhaus_link,
			reporter      = EXCLUDED.reporter,
			raw           = EXCLUDED.raw,
			last_seen_at  = now()
		WHERE urlhaus_urls.url_status IS DISTINCT FROM EXCLUDED.url_status
		   OR urlhaus_urls.last_online IS DISTINCT FROM EXCLUDED.last_online`

	// The CSV has comment lines starting with `#` before the data — we need
	// to strip them before handing the stream to encoding/csv.
	filtered := stripComments(body)
	reader := csv.NewReader(filtered)
	// abuse.ch sometimes ships rows with stray commas inside tags fields
	// already-quoted, so leave LazyQuotes off (strict) but be tolerant of
	// variable field counts.
	reader.FieldsPerRecord = -1

	processed := 0
	for {
		select {
		case <-ctx.Done():
			return processed, ctx.Err()
		default:
		}

		fields, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			slog.Warn("URLhaus CSV row skipped", "error", err)
			continue
		}
		if len(fields) < 9 {
			continue
		}

		row := UrlhausRow{
			ID:          strings.TrimSpace(fields[0]),
			DateAdded:   strings.TrimSpace(fields[1]),
			URL:         strings.TrimSpace(fields[2]),
			URLStatus:   strings.TrimSpace(fields[3]),
			LastOnline:  strings.TrimSpace(fields[4]),
			Threat:      strings.TrimSpace(fields[5]),
			Tags:        strings.TrimSpace(fields[6]),
			UrlhausLink: strings.TrimSpace(fields[7]),
			Reporter:    strings.TrimSpace(fields[8]),
		}
		if row.ID == "" || row.URL == "" {
			continue
		}

		_, err = r.db.Exec(ctx, upsertSQL,
			row.ID, row.URL, nilEmpty(row.URLStatus), nilEmpty(row.Threat),
			splitTags(row.Tags),
			parseTime(row.DateAdded), parseTime(row.LastOnline),
			nilEmpty(row.UrlhausLink), nilEmpty(row.Reporter),
			strings.Join(fields, ","),
		)
		if err != nil {
			return processed, fmt.Errorf("upsert %s: %w", row.ID, err)
		}
		processed++
	}
	return processed, nil
}

// stripComments wraps an io.Reader to elide any line that begins with `#`.
// Used to strip the abuse.ch banner before csv.Reader sees the stream.
func stripComments(in io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		defer func() { _ = pw.Close() }()
		s := bufio.NewScanner(in)
		// Default scanner buffer is 64KB; URLhaus rows are short but allow
		// for some long URLs/tags.
		s.Buffer(make([]byte, 64*1024), 1024*1024)
		for s.Scan() {
			line := s.Bytes()
			if len(line) > 0 && line[0] == '#' {
				continue
			}
			if _, err := pw.Write(line); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			if _, err := pw.Write([]byte{'\n'}); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
		}
		if err := s.Err(); err != nil {
			_ = pw.CloseWithError(err)
		}
	}()
	return pr
}

// splitTags converts a comma-separated tag list into a clean []string,
// trimming whitespace and dropping empties. Returns empty (not nil) so
// the upsert receives a valid text[] value.
func splitTags(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}

// parseTime accepts the three timestamp shapes abuse.ch returns:
//   - "2026-05-16 16:58:18"      (URLhaus + MalwareBazaar)
//   - "2026-05-16 18:46:11 UTC"  (ThreatFox — trailing TZ abbreviation)
//   - RFC3339 variants           (used elsewhere in the package)
//
// Returns nil for empty / unparseable.
func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05 MST", // ThreatFox: "... UTC" suffix
		"2006-01-02 15:04:05",     // URLhaus, MalwareBazaar
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			// abuse.ch timestamps are UTC by convention; tag them so the
			// timestamptz column round-trips correctly.
			return ptr(t.UTC())
		}
	}
	return nil
}

func ptr(t time.Time) *time.Time { return &t }

func nilEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
