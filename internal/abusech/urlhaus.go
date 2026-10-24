// Package abusech ingests the abuse.ch threat-intel feeds: URLhaus,
// ThreatFox and MalwareBazaar. All three sit behind the unified abuse.ch
// Auth-Key (AbusechConfig.APIKey), issued per account at auth.abuse.ch.
//
// URLhaus source: https://urlhaus-api.abuse.ch/v1/urls/recent/limit/<n>/
// (GET, Auth-Key header, JSON). The public CSV at
// urlhaus.abuse.ch/downloads/csv_recent/ that v1 of this runner read was
// retired by abuse.ch in October 2026 (HTTP 410), and the runner failed
// every hourly poll from the 21st until it moved here.
package abusech

import (
	"bytes"
	"context"
	"encoding/json"
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

// defaultUrlhausURL is the authenticated "recent additions" endpoint. 1000
// is the largest page the API serves; URLhaus adds a few hundred to a few
// thousand URLs a day, so an hourly poll of the newest 1000 keeps up.
const defaultUrlhausURL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"

// urlhausResponse is the envelope of /v1/urls/recent/. Entries are kept
// as raw objects: the API is loose about scalar types (`id` arrives as a
// JSON number, other fields as strings or null), so each field is read
// through asString rather than a typed struct that one drift would break.
type urlhausResponse struct {
	QueryStatus string            `json:"query_status"`
	URLs        []json.RawMessage `json:"urls"`
}

// urlhausAPIEntry is one URL as the API returns it, normalised to strings.
// Only the fields the table stores are declared; the full object is kept
// in `raw`.
type urlhausAPIEntry struct {
	ID               string
	URL              string
	URLStatus        string
	DateAdded        string // "2026-10-24 07:51:04 UTC"
	LastOnline       string // not present on /recent/; kept if it ever is
	Threat           string
	Reporter         string
	UrlhausReference string
	Tags             []string // nil when untagged
	Raw              json.RawMessage
}

// asString renders a JSON scalar the way the table wants it: strings as
// they are, whole numbers without a decimal point, bools as true/false,
// null and anything else as "".
func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func entryFromRaw(raw json.RawMessage) (urlhausAPIEntry, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return urlhausAPIEntry{}, err
	}
	e := urlhausAPIEntry{
		ID:               asString(m["id"]),
		URL:              asString(m["url"]),
		URLStatus:        asString(m["url_status"]),
		DateAdded:        asString(m["date_added"]),
		LastOnline:       asString(m["last_online"]),
		Threat:           asString(m["threat"]),
		Reporter:         asString(m["reporter"]),
		UrlhausReference: asString(m["urlhaus_reference"]),
		Raw:              raw,
	}
	if tags, ok := m["tags"].([]any); ok {
		for _, t := range tags {
			if s := asString(t); s != "" {
				e.Tags = append(e.Tags, s)
			}
		}
	}
	return e, nil
}

type UrlhausRunner struct {
	db     *pgxpool.Pool
	cfg    config.UrlhausConfig
	apiKey string
	client *http.Client
}

func NewUrlhausRunner(db *pgxpool.Pool, cfg config.UrlhausConfig, apiKey string) *UrlhausRunner {
	return &UrlhausRunner{
		db:     db,
		cfg:    cfg,
		apiKey: apiKey,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (r *UrlhausRunner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("URLhaus ingestion disabled")
		return nil
	}
	// An error rather than ThreatFox's quiet skip: URLhaus ran keyless for
	// months, so a missing key here is a regression worth a red metric.
	if r.apiKey == "" {
		return fmt.Errorf("URLhaus API requires abusech.api_key (ABUSECH_API_KEY)")
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
	req.Header.Set("Auth-Key", r.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tigerfetch/1.0 (+https://tigerblue.app)")

	httpStart := time.Now()
	resp, err := r.client.Do(req)
	metrics.UpstreamRequestDuration.WithLabelValues("urlhaus").Observe(time.Since(httpStart).Seconds())
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("fetch %s: status %d — abuse.ch rejected the Auth-Key", url, resp.StatusCode)
	default:
		return fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}

	processed, err := r.ingestJSON(ctx, resp.Body)
	if err != nil {
		return err
	}
	metrics.UrlhausRowsProcessed.Add(float64(processed))
	slog.Info("URLhaus ingestion complete", "rows", processed)
	return nil
}

// parseUrlhausResponse decodes the API envelope and returns its entries.
// "no_results" is an empty page, not an error.
func parseUrlhausResponse(body io.Reader) ([]urlhausAPIEntry, error) {
	var out urlhausResponse
	if err := json.NewDecoder(body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode URLhaus response: %w", err)
	}
	switch out.QueryStatus {
	case "ok":
	case "no_results":
		return nil, nil
	default:
		return nil, fmt.Errorf("URLhaus query_status %q", out.QueryStatus)
	}
	entries := make([]urlhausAPIEntry, 0, len(out.URLs))
	for i, raw := range out.URLs {
		e, err := entryFromRaw(raw)
		if err != nil {
			return nil, fmt.Errorf("decode URLhaus entry %d: %w", i, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (r *UrlhausRunner) ingestJSON(ctx context.Context, body io.Reader) (int, error) {
	// last_online is COALESCEd because /recent/ does not carry it: a page
	// that omits it must not blank a value an earlier load stored.
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
			last_online   = COALESCE(EXCLUDED.last_online, urlhaus_urls.last_online),
			urlhaus_link  = EXCLUDED.urlhaus_link,
			reporter      = EXCLUDED.reporter,
			raw           = EXCLUDED.raw,
			last_seen_at  = now()
		WHERE urlhaus_urls.url_status IS DISTINCT FROM EXCLUDED.url_status
		   OR (EXCLUDED.last_online IS NOT NULL
		       AND urlhaus_urls.last_online IS DISTINCT FROM EXCLUDED.last_online)`

	entries, err := parseUrlhausResponse(body)
	if err != nil {
		return 0, err
	}

	processed := 0
	for _, e := range entries {
		select {
		case <-ctx.Done():
			return processed, ctx.Err()
		default:
		}

		id, url := strings.TrimSpace(e.ID), strings.TrimSpace(e.URL)
		if id == "" || url == "" {
			continue
		}
		tags := e.Tags
		if tags == nil {
			tags = []string{}
		}

		_, err := r.db.Exec(ctx, upsertSQL,
			id, url, nilEmpty(e.URLStatus), nilEmpty(e.Threat),
			tags,
			parseTime(e.DateAdded), parseTime(e.LastOnline),
			nilEmpty(e.UrlhausReference), nilEmpty(e.Reporter),
			string(e.Raw),
		)
		if err != nil {
			return processed, fmt.Errorf("upsert %s: %w", id, err)
		}
		processed++
	}
	return processed, nil
}

// parseTime accepts the three timestamp shapes abuse.ch returns:
//   - "2026-05-16 16:58:18"      (MalwareBazaar)
//   - "2026-05-16 18:46:11 UTC"  (URLhaus API, ThreatFox — trailing TZ abbreviation)
//   - RFC3339 variants           (used elsewhere in the package)
//
// Returns nil for empty / unparseable.
func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05 MST", // URLhaus API, ThreatFox: "... UTC" suffix
		"2006-01-02 15:04:05",     // MalwareBazaar
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
