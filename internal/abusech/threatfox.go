// ThreatFox ingestor — abuse.ch's malware-family-keyed IOC feed. IPs,
// domains, URLs and hashes that URLhaus' URL-only feed doesn't cover,
// each with a 0-100 confidence score and malpedia mapping.
//
// Auth-Key header has been mandatory since 2024 (abuse.ch unified-auth
// migration). The runner short-circuits when AbusechConfig.APIKey is
// empty so the binary can still ship URLhaus-only when no key is set.
//
// API: POST https://threatfox-api.abuse.ch/api/v1/
//      body: {"query":"get_iocs","days":7}
// Docs: https://threatfox.abuse.ch/api/

package abusech

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultThreatFoxURL = "https://threatfox-api.abuse.ch/api/v1/"
	threatFoxMaxDays    = 7
)

// ThreatFoxIOC mirrors one record in the ThreatFox `get_iocs` response.
// Field types verified against a live response on 2026-05-16: `id` is
// the stringified decimal of the numeric ID column; `confidence_level`
// is a JSON number; `anonymous` is the string "0" / "1".
type ThreatFoxIOC struct {
	IocID            string   `json:"id"`
	Ioc              string   `json:"ioc"`
	ThreatType       string   `json:"threat_type"`
	IocType          string   `json:"ioc_type"`
	Malware          string   `json:"malware"`
	MalwareAlias     string   `json:"malware_alias"`
	MalwarePrintable string   `json:"malware_printable"`
	MalwareMalpedia  string   `json:"malware_malpedia"`
	ConfidenceLevel  *int     `json:"confidence_level"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	Reporter         string   `json:"reporter"`
	Reference        string   `json:"reference"`
	Tags             []string `json:"tags"`
	Anonymous        string   `json:"anonymous"`
}

type threatFoxResponse struct {
	QueryStatus string         `json:"query_status"`
	Data        []ThreatFoxIOC `json:"data"`
}

type ThreatFoxRunner struct {
	db     *pgxpool.Pool
	cfg    config.ThreatFoxConfig
	apiKey string
	client *http.Client
}

func NewThreatFoxRunner(db *pgxpool.Pool, cfg config.ThreatFoxConfig, apiKey string) *ThreatFoxRunner {
	// abuse.ch's ThreatFox endpoint enforces HTTP/2 — forcing HTTP/1.1
	// triggers `http2_handshake_failed` from the server. Stick with the
	// default Transport (h2 + h1 negotiated via ALPN). The observed
	// RST_STREAM(INTERNAL_ERROR) is handled by the postOnce + retry
	// path in Run().
	return &ThreatFoxRunner{
		db:     db,
		cfg:    cfg,
		apiKey: apiKey,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (r *ThreatFoxRunner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("ThreatFox ingestion disabled")
		return nil
	}
	if r.apiKey == "" {
		slog.Warn("ThreatFox ingestion skipped — no abuse.ch API key configured")
		return nil
	}

	start := time.Now()
	defer func() {
		metrics.ThreatFoxRunDuration.Observe(time.Since(start).Seconds())
		if retErr != nil {
			metrics.ThreatFoxFetches.WithLabelValues("error").Inc()
		} else {
			metrics.ThreatFoxFetches.WithLabelValues("success").Inc()
		}
	}()

	url := r.cfg.URL
	if url == "" {
		url = defaultThreatFoxURL
	}
	days := r.cfg.Days
	if days <= 0 || days > threatFoxMaxDays {
		days = threatFoxMaxDays
	}

	body, err := json.Marshal(map[string]any{
		"query": "get_iocs",
		"days":  days,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	respBytes, err := r.postOnce(ctx, url, body)
	if isTransientReadError(err) {
		slog.Warn("ThreatFox transient error, retrying once after 2s", "error", err)
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
		respBytes, err = r.postOnce(ctx, url, body)
	}
	if err != nil {
		return err
	}

	var parsed threatFoxResponse
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	// abuse.ch surfaces "no_result" / "illegal_auth" / etc. via query_status
	// rather than HTTP status codes. Treat anything other than "ok" / "no_result"
	// as an error so the metric label is honest.
	switch parsed.QueryStatus {
	case "ok":
	case "no_result":
		slog.Info("ThreatFox returned no results for window", "days", days)
		return nil
	default:
		return fmt.Errorf("threatfox query_status=%s", parsed.QueryStatus)
	}

	processed, err := r.upsertAll(ctx, parsed.Data)
	if err != nil {
		return err
	}
	metrics.ThreatFoxIocsProcessed.Add(float64(processed))
	slog.Info("ThreatFox ingestion complete", "iocs", processed, "days", days)
	return nil
}

func (r *ThreatFoxRunner) upsertAll(ctx context.Context, iocs []ThreatFoxIOC) (int, error) {
	const upsertSQL = `
		INSERT INTO threatfox_iocs (
			ioc_id, ioc, ioc_type, threat_type,
			malware, malware_alias, malware_printable, malware_malpedia,
			confidence_level, first_seen, last_seen,
			reporter, reference, tags, anonymous,
			raw, last_seen_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11,
			$12, $13, $14, $15,
			$16::jsonb, now()
		)
		ON CONFLICT (ioc_id) DO UPDATE SET
			ioc               = EXCLUDED.ioc,
			ioc_type          = EXCLUDED.ioc_type,
			threat_type       = EXCLUDED.threat_type,
			malware           = EXCLUDED.malware,
			malware_alias     = EXCLUDED.malware_alias,
			malware_printable = EXCLUDED.malware_printable,
			malware_malpedia  = EXCLUDED.malware_malpedia,
			confidence_level  = EXCLUDED.confidence_level,
			first_seen        = EXCLUDED.first_seen,
			last_seen         = EXCLUDED.last_seen,
			reporter          = EXCLUDED.reporter,
			reference         = EXCLUDED.reference,
			tags              = EXCLUDED.tags,
			anonymous         = EXCLUDED.anonymous,
			raw               = EXCLUDED.raw,
			last_seen_at      = now()
		WHERE threatfox_iocs.last_seen IS DISTINCT FROM EXCLUDED.last_seen
		   OR threatfox_iocs.confidence_level IS DISTINCT FROM EXCLUDED.confidence_level`

	processed := 0
	for _, ioc := range iocs {
		select {
		case <-ctx.Done():
			return processed, ctx.Err()
		default:
		}

		id, err := strconv.ParseInt(strings.TrimSpace(ioc.IocID), 10, 64)
		if err != nil || strings.TrimSpace(ioc.Ioc) == "" {
			continue
		}

		raw, err := json.Marshal(ioc)
		if err != nil {
			return processed, fmt.Errorf("marshal raw: %w", err)
		}

		_, err = r.db.Exec(ctx, upsertSQL,
			id,
			ioc.Ioc,
			ioc.IocType,
			nilEmpty(ioc.ThreatType),
			nilEmpty(ioc.Malware),
			nilEmpty(ioc.MalwareAlias),
			nilEmpty(ioc.MalwarePrintable),
			nilEmpty(ioc.MalwareMalpedia),
			ioc.ConfidenceLevel,
			parseTime(ioc.FirstSeen),
			parseTime(ioc.LastSeen),
			nilEmpty(ioc.Reporter),
			nilEmpty(ioc.Reference),
			normaliseTags(ioc.Tags),
			parseBoolish(ioc.Anonymous),
			raw,
		)
		if err != nil {
			return processed, fmt.Errorf("upsert %d: %w", id, err)
		}
		processed++
	}
	return processed, nil
}

// postOnce issues a single POST + body read, returning the raw bytes.
// Pulled out of Run so the call site can retry without duplicating the
// request setup. body is the raw JSON to POST; we wrap it in a fresh
// bytes.Reader each call so the second attempt restarts cleanly.
func (r *ThreatFoxRunner) postOnce(ctx context.Context, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", r.apiKey)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("post %s: status %d: %s", url, resp.StatusCode, string(b))
	}

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return out, nil
}

// isTransientReadError flags errors worth one retry. We force HTTP/1.1
// for ThreatFox (see NewThreatFoxRunner), but keep this guard so any
// short read / unexpected EOF / connection-reset gets a second chance
// before the 1h-cadence run gives up.
func isTransientReadError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, needle := range []string{
		"stream error",      // http2 RST_STREAM
		"INTERNAL_ERROR",    // http2 error code names
		"unexpected EOF",    // truncated body
		"connection reset",  // mid-flight network drop
		"broken pipe",
	} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// parseBoolish handles abuse.ch's "0"/"1"/"true"/"false" string encoding
// for the `anonymous` field. Defaults to false on anything unrecognised.
func parseBoolish(s string) bool {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// normaliseTags drops empty/whitespace-only entries. Returns an empty
// (non-nil) slice so the text[] upsert receives a valid value.
func normaliseTags(in []string) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}
