// Package nuclei ingests ProjectDiscovery Nuclei templates from the
// github.com/projectdiscovery/nuclei-templates repository.
//
// The signal: when a CVE gets a Nuclei template, exploit availability has
// crossed a scanner-distribution threshold — every commodity scanner that
// uses Nuclei now finds it. Tracking template additions runs 2–6 weeks
// ahead of EPSS movement in practice (and frequently lands the same day
// as the upstream vendor patch).
//
// Strategy: download the main-branch tarball once per cycle (~50 MB),
// stream-decompress + tar-walk in-memory, parse every YAML matching
// `**/*.yaml` under the configured subdirs, extract the minimum metadata
// needed for analysis (id, name, severity, authors, CVEs, CWEs, tags).
//
// Source: https://github.com/projectdiscovery/nuclei-templates
package nuclei

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"gopkg.in/yaml.v3"
)

const defaultTarballURL = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz"

// cveRegexp matches `CVE-YYYY-NNNNN[+]` anywhere in a string. Used to pull
// CVE references out of the template id, filename, and the `tags` field.
var cveRegexp = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// cweRegexp matches `CWE-NNN` (1-4 digits).
var cweRegexp = regexp.MustCompile(`CWE-\d{1,4}`)

// Template is the subset of the Nuclei YAML schema we denormalise.
// The full source YAML is preserved in `raw`.
type Template struct {
	ID   string       `yaml:"id"`
	Info TemplateInfo `yaml:"info"`
}

type TemplateInfo struct {
	Name           string         `yaml:"name"`
	Author         yaml.Node      `yaml:"author"` // can be string OR []string
	Severity       string         `yaml:"severity"`
	Description    string         `yaml:"description"`
	Tags           yaml.Node      `yaml:"tags"` // string OR []string
	Classification Classification `yaml:"classification"`
}

type Classification struct {
	CveID yaml.Node `yaml:"cve-id"` // string OR []string
	CweID yaml.Node `yaml:"cwe-id"` // string OR []string
}

type Runner struct {
	db     *pgxpool.Pool
	cfg    config.NucleiConfig
	client *http.Client
}

func NewRunner(db *pgxpool.Pool, cfg config.NucleiConfig) *Runner {
	return &Runner{
		db:  db,
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Minute, // tarball is ~50 MB; allow generous time
		},
	}
}

// defaultSubdirs is the list of repo subdirectories we walk when the
// caller didn't pin a list in config. These cover the template families
// that map to known threat-intel pivot keys; the experimental / network
// / file / etc. dirs can be added later.
var defaultSubdirs = []string{
	"http/cves/",
	"http/vulnerabilities/",
	"dns/",
	"network/cves/",
	"file/",
	"javascript/cves/",
	"ssl/",
}

func (r *Runner) Run(ctx context.Context) (retErr error) {
	if !r.cfg.Enabled {
		slog.Info("Nuclei ingestion disabled")
		return nil
	}

	start := time.Now()
	defer func() {
		metrics.NucleiRunDuration.Observe(time.Since(start).Seconds())
		if retErr != nil {
			metrics.NucleiFetches.WithLabelValues("error").Inc()
		} else {
			metrics.NucleiFetches.WithLabelValues("success").Inc()
		}
	}()

	url := r.cfg.URL
	if url == "" {
		url = defaultTarballURL
	}
	subdirs := r.cfg.Subdirs
	if len(subdirs) == 0 {
		subdirs = defaultSubdirs
	}

	slog.Info("Nuclei fetching tarball", "url", url)
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

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()

	processed, err := r.persistTarball(ctx, tar.NewReader(gz), subdirs)
	if err != nil {
		return err
	}
	metrics.NucleiTemplatesProcessed.Add(float64(processed))
	slog.Info("Nuclei ingestion complete", "templates", processed)
	return nil
}

func (r *Runner) persistTarball(ctx context.Context, tr *tar.Reader, subdirs []string) (int, error) {
	const upsertSQL = `
		INSERT INTO nuclei_templates (
			template_id, name, severity, template_path,
			authors, description, cves, cwes, tags,
			yaml_sha256, raw, last_seen_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8, $9,
			$10, $11, now()
		)
		ON CONFLICT (template_id) DO UPDATE SET
			name           = EXCLUDED.name,
			severity       = EXCLUDED.severity,
			template_path  = EXCLUDED.template_path,
			authors        = EXCLUDED.authors,
			description    = EXCLUDED.description,
			cves           = EXCLUDED.cves,
			cwes           = EXCLUDED.cwes,
			tags           = EXCLUDED.tags,
			yaml_sha256    = EXCLUDED.yaml_sha256,
			raw            = EXCLUDED.raw,
			last_seen_at   = now()
		WHERE nuclei_templates.yaml_sha256 IS DISTINCT FROM EXCLUDED.yaml_sha256`

	processed := 0
	for {
		select {
		case <-ctx.Done():
			return processed, ctx.Err()
		default:
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return processed, fmt.Errorf("tar walk: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !strings.HasSuffix(hdr.Name, ".yaml") && !strings.HasSuffix(hdr.Name, ".yml") {
			continue
		}
		// hdr.Name looks like `nuclei-templates-main/http/cves/2024/CVE-2024-12345.yaml`
		// — strip the leading repo dir before subdir filtering.
		rel := stripLeadingDir(hdr.Name)
		if !matchesSubdirs(rel, subdirs) {
			continue
		}

		body, err := io.ReadAll(tr)
		if err != nil {
			return processed, fmt.Errorf("read %s: %w", hdr.Name, err)
		}

		tpl, err := parseTemplate(body)
		if err != nil {
			slog.Warn("Nuclei skipping malformed template", "path", rel, "error", err)
			continue
		}
		if tpl.ID == "" {
			// Without an id we have nothing stable to key the row on.
			continue
		}

		sum := sha256.Sum256(body)
		sha := hex.EncodeToString(sum[:])
		cves := extractCves(tpl, rel)
		cwes := extractCwes(tpl)
		tags := flattenStringNode(tpl.Info.Tags)
		authors := flattenStringNode(tpl.Info.Author)

		// Postgres text/jsonb refuses literal NUL bytes (0x00). Some
		// Nuclei templates carry NULs in their payload examples — strip
		// before insert. Cheap, doesn't affect non-NUL content.
		_, err = r.db.Exec(ctx, upsertSQL,
			stripNUL(tpl.ID), nilEmpty(stripNUL(tpl.Info.Name)),
			nilEmpty(strings.ToLower(stripNUL(tpl.Info.Severity))), stripNUL(rel),
			authors, nilEmpty(stripNUL(tpl.Info.Description)), cves, cwes, tags,
			sha, stripNUL(string(body)),
		)
		if err != nil {
			return processed, fmt.Errorf("upsert %s: %w", tpl.ID, err)
		}
		processed++
	}
	return processed, nil
}

func parseTemplate(b []byte) (Template, error) {
	var t Template
	if err := yaml.Unmarshal(b, &t); err != nil {
		return Template{}, err
	}
	return t, nil
}

// stripLeadingDir removes the top-level repo directory from a tar entry
// path, e.g. "nuclei-templates-main/http/cves/foo.yaml" → "http/cves/foo.yaml".
func stripLeadingDir(p string) string {
	if i := strings.Index(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// matchesSubdirs reports whether `path` (relative to repo root) sits
// under any of the configured prefixes.
func matchesSubdirs(path string, subdirs []string) bool {
	for _, s := range subdirs {
		if strings.HasPrefix(path, s) {
			return true
		}
	}
	return false
}

// extractCves collects CVE refs from (1) classification.cve-id, (2) the
// tags list, and (3) the template id / file path itself. Dedup + uppercase.
func extractCves(t Template, path string) []string {
	seen := map[string]struct{}{}
	add := func(v string) {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" {
			return
		}
		seen[v] = struct{}{}
	}

	for _, v := range flattenStringNode(t.Info.Classification.CveID) {
		for _, m := range cveRegexp.FindAllString(v, -1) {
			add(m)
		}
	}
	for _, v := range flattenStringNode(t.Info.Tags) {
		for _, m := range cveRegexp.FindAllString(v, -1) {
			add(m)
		}
	}
	for _, m := range cveRegexp.FindAllString(t.ID, -1) {
		add(m)
	}
	for _, m := range cveRegexp.FindAllString(path, -1) {
		add(m)
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func extractCwes(t Template) []string {
	seen := map[string]struct{}{}
	for _, v := range flattenStringNode(t.Info.Classification.CweID) {
		for _, m := range cweRegexp.FindAllString(strings.ToUpper(v), -1) {
			seen[m] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// flattenStringNode handles the Nuclei YAML quirk where a field can be
// either a single string or a list of strings. Returns a clean []string
// (empty, never nil) with whitespace trimmed.
func flattenStringNode(n yaml.Node) []string {
	out := []string{}
	switch n.Kind {
	case yaml.ScalarNode:
		v := strings.TrimSpace(n.Value)
		if v == "" {
			return out
		}
		// `tags` is typically a comma-separated scalar like "cve,2024,oast".
		for _, p := range strings.Split(v, ",") {
			t := strings.TrimSpace(p)
			if t != "" {
				out = append(out, t)
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				if v := strings.TrimSpace(c.Value); v != "" {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

func nilEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// stripNUL removes literal NUL bytes from a string. Postgres' text and
// jsonb types reject 0x00, but some Nuclei templates carry NULs in their
// payload examples (binary fuzzers, raw exploit blobs).
func stripNUL(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}
