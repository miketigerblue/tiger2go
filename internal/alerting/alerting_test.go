package alerting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"tiger2go/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSlackPayload(t *testing.T) {
	sleepers := []SleeperCVE{
		{
			CVEID:       "CVE-2025-71243",
			EpssBefore:  0.0011,
			EpssNow:     0.8368,
			Delta:       0.8357,
			PctChange:   75284.0,
			Percentile:  0.9662,
			DateBefore:  "2026-03-04",
			DateNow:     "2026-04-11",
			Description: "SPIP plugin RCE",
		},
	}

	body, err := buildSlackPayload(sleepers)
	require.NoError(t, err)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &payload))

	blocks, ok := payload["blocks"].([]interface{})
	require.True(t, ok, "expected blocks array")
	assert.GreaterOrEqual(t, len(blocks), 4, "header + context + divider + 1 CVE")
}

func TestBuildGenericPayload(t *testing.T) {
	sleepers := []SleeperCVE{
		{
			CVEID:      "CVE-2025-71243",
			EpssBefore: 0.0011,
			EpssNow:    0.8368,
			Delta:      0.8357,
		},
		{
			CVEID:      "CVE-2025-50286",
			EpssBefore: 0.009,
			EpssNow:    0.584,
			Delta:      0.575,
		},
	}

	body, err := buildGenericPayload(sleepers)
	require.NoError(t, err)

	var payload genericPayload
	require.NoError(t, json.Unmarshal(body, &payload))

	assert.Equal(t, "sleeper_cve_alert", payload.Event)
	assert.Equal(t, 2, payload.Count)
	assert.Equal(t, "CVE-2025-71243", payload.Sleepers[0].CVEID)
}

func TestWebhookSender_Send(t *testing.T) {
	var called atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, http.MethodPost, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sender := NewWebhookSender(config.WebhookConfig{
		Name: "test",
		URL:  ts.URL,
		Type: "generic",
	})

	sleepers := []SleeperCVE{{CVEID: "CVE-2025-99999", EpssBefore: 0.01, EpssNow: 0.55}}

	err := sender.Send(context.Background(), sleepers)
	require.NoError(t, err)
	assert.Equal(t, int32(1), called.Load())
}

func TestWebhookSender_SlackType(t *testing.T) {
	var receivedBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		receivedBody = buf[:n]
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sender := NewWebhookSender(config.WebhookConfig{
		Name: "slack-test",
		URL:  ts.URL,
		Type: "slack",
	})

	sleepers := []SleeperCVE{
		{
			CVEID:       "CVE-2025-71243",
			EpssBefore:  0.001,
			EpssNow:     0.84,
			DateBefore:  "2026-03-04",
			DateNow:     "2026-04-11",
			Description: "Test vuln",
		},
	}

	err := sender.Send(context.Background(), sleepers)
	require.NoError(t, err)

	// Verify it's a Slack blocks payload
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(receivedBody, &payload))
	_, hasBlocks := payload["blocks"]
	assert.True(t, hasBlocks, "Slack payload must contain blocks")
}

func TestWebhookSender_ErrorOnBadStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	sender := NewWebhookSender(config.WebhookConfig{
		Name: "failing",
		URL:  ts.URL,
		Type: "generic",
	})

	err := sender.Send(context.Background(), []SleeperCVE{{CVEID: "CVE-2025-00001"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestBuildSlackPayload_TruncatesLongDescriptions(t *testing.T) {
	longDesc := ""
	for i := 0; i < 200; i++ {
		longDesc += "x"
	}

	sleepers := []SleeperCVE{
		{
			CVEID:       "CVE-2025-00001",
			EpssBefore:  0.01,
			EpssNow:     0.60,
			DateBefore:  "2026-03-04",
			DateNow:     "2026-04-11",
			Description: longDesc,
		},
	}

	body, err := buildSlackPayload(sleepers)
	require.NoError(t, err)
	// The full 200-char description should not appear
	assert.NotContains(t, string(body), longDesc)
	assert.Contains(t, string(body), "...")
}

func TestBuildSlackPayload_CapsAt10(t *testing.T) {
	sleepers := make([]SleeperCVE, 15)
	for i := range sleepers {
		sleepers[i] = SleeperCVE{
			CVEID:      "CVE-2025-00001",
			EpssBefore: 0.01,
			EpssNow:    0.55,
			DateBefore: "2026-03-04",
			DateNow:    "2026-04-11",
		}
	}

	body, err := buildSlackPayload(sleepers)
	require.NoError(t, err)
	assert.Contains(t, string(body), "and 5 more")
}
