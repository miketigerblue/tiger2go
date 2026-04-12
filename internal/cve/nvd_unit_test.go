package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"tiger2go/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// extractCvssScore
// ---------------------------------------------------------------------------

func TestExtractCvssScore_V31(t *testing.T) {
	raw := json.RawMessage(`{
		"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
	}`)
	score := extractCvssScore(raw)
	require.NotNil(t, score)
	assert.Equal(t, 9.8, *score)
}

func TestExtractCvssScore_V30Fallback(t *testing.T) {
	raw := json.RawMessage(`{
		"cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}]
	}`)
	score := extractCvssScore(raw)
	require.NotNil(t, score)
	assert.Equal(t, 7.5, *score)
}

func TestExtractCvssScore_V31PreferredOverV30(t *testing.T) {
	raw := json.RawMessage(`{
		"cvssMetricV31": [{"cvssData": {"baseScore": 9.0}}],
		"cvssMetricV30": [{"cvssData": {"baseScore": 7.0}}]
	}`)
	score := extractCvssScore(raw)
	require.NotNil(t, score)
	assert.Equal(t, 9.0, *score)
}

func TestExtractCvssScore_Empty(t *testing.T) {
	assert.Nil(t, extractCvssScore(nil))
	assert.Nil(t, extractCvssScore(json.RawMessage("")))
	assert.Nil(t, extractCvssScore(json.RawMessage("{}")))
}

func TestExtractCvssScore_InvalidJSON(t *testing.T) {
	raw := json.RawMessage(`not json`)
	assert.Nil(t, extractCvssScore(raw))
}

func TestExtractCvssScore_EmptyArrays(t *testing.T) {
	raw := json.RawMessage(`{
		"cvssMetricV31": [],
		"cvssMetricV30": []
	}`)
	assert.Nil(t, extractCvssScore(raw))
}

// ---------------------------------------------------------------------------
// fetchWithRetry
// ---------------------------------------------------------------------------

func TestFetchWithRetry_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"totalResults": 0}`))
	}))
	defer ts.Close()

	runner := &NvdRunner{
		cfg:    config.NvdConfig{},
		client: &http.Client{Timeout: 5 * time.Second},
	}

	data, err := runner.fetchWithRetry(context.Background(), ts.URL)
	require.NoError(t, err)
	assert.Contains(t, string(data), "totalResults")
}

func TestFetchWithRetry_ApiKeyHeader(t *testing.T) {
	var gotKey string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("apiKey")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	runner := &NvdRunner{
		cfg:    config.NvdConfig{ApiKey: "test-key-123"},
		client: &http.Client{Timeout: 5 * time.Second},
	}

	_, err := runner.fetchWithRetry(context.Background(), ts.URL)
	require.NoError(t, err)
	assert.Equal(t, "test-key-123", gotKey)
}

func TestFetchWithRetry_RetriesOn429(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer ts.Close()

	runner := &NvdRunner{
		cfg:    config.NvdConfig{},
		client: &http.Client{Timeout: 5 * time.Second},
	}

	// Use a short-lived context so the test doesn't take long
	// The backoff sleeps are bypassed by context-aware select
	data, err := runner.fetchWithRetry(context.Background(), ts.URL)
	require.NoError(t, err)
	assert.Contains(t, string(data), "ok")
	assert.Equal(t, int32(3), attempts.Load())
}

func TestFetchWithRetry_RespectsContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	runner := &NvdRunner{
		cfg:    config.NvdConfig{},
		client: &http.Client{Timeout: 5 * time.Second},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := runner.fetchWithRetry(ctx, ts.URL)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestFetchWithRetry_UnexpectedStatusCode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	runner := &NvdRunner{
		cfg:    config.NvdConfig{},
		client: &http.Client{Timeout: 5 * time.Second},
	}

	_, err := runner.fetchWithRetry(context.Background(), ts.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code: 403")
}
