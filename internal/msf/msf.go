// Package msf ingests Metasploit Framework module metadata from the
// pre-extracted JSON cache that Rapid7 ships in their repository.
//
// The signal: when a CVE gets a Metasploit module, weaponised exploit
// availability is confirmed (not just a scanner check like Nuclei).
// Modules carry ranking metadata that distinguishes reliability:
// excellent / great / good / normal / average / low / manual.
//
// Source: https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json
// (single ~10 MB JSON file with all module metadata pre-extracted).
package msf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultURL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

// cveRegexp matches CVE-YYYY-NNNNN anywhere in a string. Used to pull
// CVE IDs out of MSF's free-form `references` list (which mixes
// "CVE-2024-1234", "OSVDB-12345", "URL-…", "EDB-50000").
var cveRegexp = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// Rank ↔ label mapping (Metasploit constant ranks).
var rankLabels = map[int]string{
	0:   "manual",
	100: "low",
	200: "average",
	300: "normal",
	400: "good",
	500: "great",
	600: "excellent",
}

// Module is the subset of the upstream JSON we denormalise. The full
// record is preserved in the `raw` jsonb column.
type Module struct {
	Name           string   `json:"name"`
	FullName       string   `json:"fullname"`
	Aliases        []string `json:"aliases"`
	Rank           int      `json:"rank"`
	DisclosureDate string   `json:"disclosure_date"`
	Type           string   `json:"type"`
	Author         []string `json:"author"`
	Description    string   `json:"description"`
	References     []string `json:"references"`
	Platform       string   `json:"platform"`
}

type Runner struct {
	db     *pgxpool.Pool
	cfg    config.MsfConfig
	client *http.Client
}

func NewRunner(db *pgxpool.Pool, cfg config.MsfConfig) *Runner {
	return &Runner{
		db:  db,
		cfg: cfg,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

func (r *Runner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("Metasploit metadata ingestion disabled")
		return nil
	}

	start := time.Now()
	defer func() {
		metrics.MsfRunDuration.Observe(time.Since(start).Seconds())
		if retErr != nil {
			metrics.MsfFetches.WithLabelValues("error").Inc()
		} else {
			metrics.MsfFetches.WithLabelValues("success").Inc()
		}
	}()

	url := r.cfg.URL
	if url == "" {
		url = defaultURL
	}

	slog.Info("MSF fetching metadata", "url", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	// modules_metadata_base.json is a single JSON object keyed by fullname.
	var modules map[string]json.RawMessage
	if err := json.Unmarshal(body, &modules); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	processed := 0
	for fullname, raw := range modules {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var m Module
		if err := json.Unmarshal(raw, &m); err != nil {
			slog.Warn("MSF skipping malformed module", "fullname", fullname, "error", err)
			continue
		}
		// fullname inside the object should match the key; defensively prefer the key
		// when the value is missing.
		if m.FullName == "" {
			m.FullName = fullname
		}
		if err := r.upsert(ctx, m, raw); err != nil {
			return fmt.Errorf("upsert %s: %w", m.FullName, err)
		}
		processed++
	}

	metrics.MsfModulesProcessed.Add(float64(processed))
	slog.Info("MSF ingestion complete", "modules", processed)
	return nil
}

func (r *Runner) upsert(ctx context.Context, m Module, raw json.RawMessage) error {
	const sql = `
		INSERT INTO msf_modules (
			fullname, name, module_type, rank, rank_label, disclosure_date,
			description, authors, refs, cves, platforms, aliases, raw, last_seen_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12, $13::jsonb, now()
		)
		ON CONFLICT (fullname) DO UPDATE SET
			name             = EXCLUDED.name,
			module_type      = EXCLUDED.module_type,
			rank             = EXCLUDED.rank,
			rank_label       = EXCLUDED.rank_label,
			disclosure_date  = EXCLUDED.disclosure_date,
			description      = EXCLUDED.description,
			authors          = EXCLUDED.authors,
			refs             = EXCLUDED.refs,
			cves             = EXCLUDED.cves,
			platforms        = EXCLUDED.platforms,
			aliases          = EXCLUDED.aliases,
			raw              = EXCLUDED.raw,
			last_seen_at     = now()
		WHERE msf_modules.raw IS DISTINCT FROM EXCLUDED.raw`

	disclosure := parseDate(m.DisclosureDate)
	cves := extractCves(m.References)
	platforms := splitPlatform(m.Platform)
	label := rankLabels[m.Rank] // empty string if unknown rank value

	_, err := r.db.Exec(ctx, sql,
		stripNUL(m.FullName), nilEmpty(stripNUL(m.Name)), nilEmpty(stripNUL(m.Type)),
		m.Rank, nilEmpty(label), disclosure,
		nilEmpty(stripNUL(m.Description)),
		sanitizeAll(m.Author),
		sanitizeAll(m.References),
		cves,
		platforms,
		sanitizeAll(m.Aliases),
		raw,
	)
	return err
}

// extractCves pulls CVE refs out of MSF's references list, e.g.
// ["CVE-2024-1234", "OSVDB-12345", "URL-https://..."] → ["CVE-2024-1234"].
// Uppercases + dedupes.
func extractCves(refs []string) []string {
	seen := map[string]struct{}{}
	for _, r := range refs {
		for _, m := range cveRegexp.FindAllString(strings.ToUpper(r), -1) {
			seen[m] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// splitPlatform turns MSF's free-form Platform field (e.g. "linux,windows"
// or just "linux") into a clean []string.
func splitPlatform(p string) []string {
	p = strings.TrimSpace(p)
	if p == "" {
		return []string{}
	}
	parts := strings.Split(p, ",")
	out := make([]string, 0, len(parts))
	for _, q := range parts {
		t := strings.TrimSpace(strings.ToLower(q))
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// parseDate accepts the MSF disclosure_date format ("2024-01-15") plus a
// couple of common variations. Returns nil for empty or unparseable.
func parseDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{"2006-01-02", "2006/01/02", "01/02/2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

func sanitizeAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = stripNUL(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// stripNUL removes literal NUL bytes from a string. Postgres' text type
// rejects 0x00 and some MSF descriptions / author fields contain it
// (multibyte-encoded names that landed badly in upstream extraction).
func stripNUL(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

func nilEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
