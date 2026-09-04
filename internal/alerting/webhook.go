package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"tiger2go/internal/config"
)

// WebhookSender sends alert payloads to configured endpoints.
type WebhookSender struct {
	cfg    config.WebhookConfig
	client *http.Client
}

// NewWebhookSender creates a sender for a webhook config.
func NewWebhookSender(cfg config.WebhookConfig) WebhookSender {
	return WebhookSender{
		cfg: cfg,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Name returns the webhook's configured name.
func (w WebhookSender) Name() string { return w.cfg.Name }

// Send dispatches sleeper CVE alerts to the webhook endpoint.
func (w WebhookSender) Send(ctx context.Context, sleepers []SleeperCVE) error {
	var body []byte
	var err error

	switch strings.ToLower(w.cfg.Type) {
	case "slack":
		body, err = buildSlackPayload(sleepers)
	default:
		body, err = buildGenericPayload(sleepers)
	}
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

// --- Slack Block Kit payload ---

// formatCvssBadge renders the score with its version family. The colour
// bands are the family's own: v2.0 tops out at HIGH (7.0+), so a v2 score
// is never painted CRITICAL, and anything that is not v3.x says so in the
// badge because a bare "CVSS 9.3" reads as v3 to every analyst.
func formatCvssBadge(score *float64, severity, version string) string {
	if score == nil {
		return "CVSS: _n/a_"
	}
	isV2 := version == "2.0"
	var emoji string
	switch {
	case *score >= 9.0 && !isV2:
		emoji = ":red_circle:"
	case *score >= 7.0:
		emoji = ":large_orange_circle:"
	case *score >= 4.0:
		emoji = ":large_yellow_circle:"
	default:
		emoji = ":large_green_circle:"
	}
	var tags []string
	if severity != "" {
		tags = append(tags, severity)
	}
	if version != "" && !strings.HasPrefix(version, "3.") {
		tags = append(tags, "v"+version)
	}
	if len(tags) > 0 {
		return fmt.Sprintf("%s CVSS *%.1f* (%s)", emoji, *score, strings.Join(tags, ", "))
	}
	return fmt.Sprintf("%s CVSS *%.1f*", emoji, *score)
}

// formatSsvc surfaces CISA's exploitation assertion next to the score —
// it is the one field on the row that speaks to the alert's premise.
func formatSsvc(exploitation string) string {
	switch exploitation {
	case "active":
		return " | :rotating_light: CISA SSVC: *active exploitation*"
	case "poc":
		return " | :test_tube: CISA SSVC: public PoC"
	default:
		return ""
	}
}

func formatCWE(cwe string) string {
	if cwe == "" || cwe == "NVD-CWE-noinfo" || cwe == "NVD-CWE-Other" {
		return ""
	}
	return fmt.Sprintf(" | %s", cwe)
}

func buildSlackPayload(sleepers []SleeperCVE) ([]byte, error) {
	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]string{
				"type": "plain_text",
				"text": fmt.Sprintf("Sleeper CVE Alert — %d CVEs crossed 50%% EPSS", len(sleepers)),
			},
		},
		{
			"type": "context",
			"elements": []map[string]string{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf(
						"Baseline *%s* vs *%s* (%d-day lookback) | tigerfetch",
						sleepers[0].DateBefore, sleepers[0].DateNow,
						daysBetween(sleepers[0].DateBefore, sleepers[0].DateNow),
					),
				},
			},
		},
		{"type": "divider"},
	}

	// Cap at 10 to stay within Slack block limits
	limit := len(sleepers)
	if limit > 10 {
		limit = 10
	}

	for _, s := range sleepers[:limit] {
		desc := s.Description
		if len(desc) > 200 {
			desc = desc[:197] + "..."
		}

		nvdLink := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", s.CVEID)

		// Line 1: CVE ID (linked) + CVSS badge + CWE
		line1 := fmt.Sprintf("*<%s|%s>*  %s%s%s",
			nvdLink, s.CVEID,
			formatCvssBadge(s.CvssScore, s.CvssSeverity, s.CvssVersion),
			formatCWE(s.CWE),
			formatSsvc(s.SsvcExploitation),
		)

		// Line 2: EPSS trajectory
		line2 := fmt.Sprintf(
			"EPSS: %.2f%% :arrow_right: *%.2f%%*  (+%.0f%%)  |  Percentile: *%.0f*",
			s.EpssBefore*100, s.EpssNow*100, s.PctChange, s.Percentile*100,
		)

		// Line 3: Description
		line3 := ""
		if desc != "" {
			line3 = fmt.Sprintf("\n>%s", desc)
		}

		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("%s\n%s%s", line1, line2, line3),
			},
		})

		blocks = append(blocks, map[string]interface{}{"type": "divider"})
	}

	if len(sleepers) > 10 {
		blocks = append(blocks, map[string]interface{}{
			"type": "context",
			"elements": []map[string]string{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("_...and %d more. Query your TigerFetch database for the full list._", len(sleepers)-10),
				},
			},
		})
	}

	payload := map[string]interface{}{"blocks": blocks}
	return json.Marshal(payload)
}

func daysBetween(a, b string) int {
	ta, err1 := time.Parse("2006-01-02", a)
	tb, err2 := time.Parse("2006-01-02", b)
	if err1 != nil || err2 != nil {
		return 0
	}
	return int(tb.Sub(ta).Hours() / 24)
}

// --- Generic JSON payload ---

type genericPayload struct {
	Event     string       `json:"event"`
	Timestamp string       `json:"timestamp"`
	Count     int          `json:"count"`
	Sleepers  []genericCVE `json:"sleepers"`
}

type genericCVE struct {
	CVEID            string   `json:"cve_id"`
	EpssBefore       float64  `json:"epss_before"`
	EpssNow          float64  `json:"epss_now"`
	Delta            float64  `json:"delta"`
	PctChange        float64  `json:"pct_change"`
	Percentile       float64  `json:"percentile"`
	DateBefore       string   `json:"date_before"`
	DateNow          string   `json:"date_now"`
	Description      string   `json:"description"`
	CvssScore        *float64 `json:"cvss_score"`
	CvssVersion      string   `json:"cvss_version"`
	CvssSeverity     string   `json:"cvss_severity"`
	CWE              string   `json:"cwe"`
	SsvcExploitation string   `json:"ssvc_exploitation"`
	Published        string   `json:"published"`
}

func buildGenericPayload(sleepers []SleeperCVE) ([]byte, error) {
	out := genericPayload{
		Event:     "sleeper_cve_alert",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Count:     len(sleepers),
		Sleepers:  make([]genericCVE, len(sleepers)),
	}
	for i, s := range sleepers {
		out.Sleepers[i] = genericCVE(s)
	}
	return json.Marshal(out)
}
