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
					"text": fmt.Sprintf("Comparing *%s* to *%s* | tigerfetch", sleepers[0].DateBefore, sleepers[0].DateNow),
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
		if len(desc) > 120 {
			desc = desc[:117] + "..."
		}

		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf(
					"*%s*\n%.2f%% → *%.2f%%* (+%.0f%%) | P%.0f\n_%s_",
					s.CVEID,
					s.EpssBefore*100, s.EpssNow*100, s.PctChange,
					s.Percentile*100,
					desc,
				),
			},
		})
	}

	if len(sleepers) > 10 {
		blocks = append(blocks, map[string]interface{}{
			"type": "context",
			"elements": []map[string]string{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("_...and %d more_", len(sleepers)-10),
				},
			},
		})
	}

	payload := map[string]interface{}{"blocks": blocks}
	return json.Marshal(payload)
}

// --- Generic JSON payload ---

type genericPayload struct {
	Event     string       `json:"event"`
	Timestamp string       `json:"timestamp"`
	Count     int          `json:"count"`
	Sleepers  []genericCVE `json:"sleepers"`
}

type genericCVE struct {
	CVEID       string  `json:"cve_id"`
	EpssBefore  float64 `json:"epss_before"`
	EpssNow     float64 `json:"epss_now"`
	Delta       float64 `json:"delta"`
	PctChange   float64 `json:"pct_change"`
	Percentile  float64 `json:"percentile"`
	DateBefore  string  `json:"date_before"`
	DateNow     string  `json:"date_now"`
	Description string  `json:"description"`
}

func buildGenericPayload(sleepers []SleeperCVE) ([]byte, error) {
	out := genericPayload{
		Event:     "sleeper_cve_alert",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Count:     len(sleepers),
		Sleepers:  make([]genericCVE, len(sleepers)),
	}
	for i, s := range sleepers {
		out.Sleepers[i] = genericCVE{
			CVEID:       s.CVEID,
			EpssBefore:  s.EpssBefore,
			EpssNow:     s.EpssNow,
			Delta:       s.Delta,
			PctChange:   s.PctChange,
			Percentile:  s.Percentile,
			DateBefore:  s.DateBefore,
			DateNow:     s.DateNow,
			Description: s.Description,
		}
	}
	return json.Marshal(out)
}
