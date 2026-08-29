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

// ---------------------------------------------------------------------------
// parseMetrics — CVSS fallback chain and SSVC
// ---------------------------------------------------------------------------

func TestParseMetrics_V40Fallback(t *testing.T) {
	raw := json.RawMessage(`{"cvssMetricV40": [{"cvssData": {"baseScore": 8.7}}]}`)
	m := parseMetrics(raw)
	require.NotNil(t, m.CvssBase)
	assert.Equal(t, 8.7, *m.CvssBase)
	assert.Equal(t, "4.0", m.CvssVersion)
}

func TestParseMetrics_V2LastResort(t *testing.T) {
	raw := json.RawMessage(`{"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}`)
	m := parseMetrics(raw)
	require.NotNil(t, m.CvssBase)
	assert.Equal(t, 7.5, *m.CvssBase)
	// The version must be recorded: a v2 7.5 is not a v3 7.5.
	assert.Equal(t, "2.0", m.CvssVersion)
}

func TestParseMetrics_PreferenceOrder(t *testing.T) {
	raw := json.RawMessage(`{
		"cvssMetricV31": [{"cvssData": {"baseScore": 9.0}}],
		"cvssMetricV40": [{"cvssData": {"baseScore": 8.0}}],
		"cvssMetricV2":  [{"cvssData": {"baseScore": 7.0}}]
	}`)
	m := parseMetrics(raw)
	require.NotNil(t, m.CvssBase)
	assert.Equal(t, 9.0, *m.CvssBase)
	assert.Equal(t, "3.1", m.CvssVersion)
}

// An entry present but carrying no baseScore must not be read as 0.0 —
// CVSS defines 0.0 as a real score ("None").
func TestParseMetrics_MissingBaseScoreIsNotZero(t *testing.T) {
	raw := json.RawMessage(`{"cvssMetricV31": [{"cvssData": {"vectorString": "CVSS:3.1/..."}}]}`)
	m := parseMetrics(raw)
	assert.Nil(t, m.CvssBase)
	assert.Equal(t, "", m.CvssVersion)
}

func TestParseMetrics_Ssvc(t *testing.T) {
	raw := json.RawMessage(`{"ssvcV203": [{"ssvcData": {"options": [
		{"exploitation": "active"}, {"automatable": "no"},
		{"technicalImpact": "partial"}]}}]}`)
	m := parseMetrics(raw)
	assert.Equal(t, "active", m.SsvcExploitation)
	assert.Equal(t, "no", m.SsvcAutomatable)
	assert.Equal(t, "partial", m.SsvcTechnicalImpact)
}

func TestParseMetrics_Empty(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, json.RawMessage(""), json.RawMessage("{}"), json.RawMessage("not json")} {
		m := parseMetrics(raw)
		assert.Nil(t, m.CvssBase)
		assert.Equal(t, "", m.SsvcExploitation)
	}
}

// ---------------------------------------------------------------------------
// parseNvdTime
// ---------------------------------------------------------------------------

// The regression that mattered: NVD sends no timezone, RFC3339 rejects
// it, and the old code silently substituted time.Now() for every row.
func TestParseNvdTime_NaiveFormat(t *testing.T) {
	got, ok := parseNvdTime("2026-08-29T18:16:33.473")
	require.True(t, ok)
	assert.Equal(t, "2026-08-29T18:16:33Z", got.Format("2006-01-02T15:04:05Z"))
	assert.Equal(t, time.UTC, got.Location())
}

func TestParseNvdTime_SecondsPrecision(t *testing.T) {
	got, ok := parseNvdTime("2026-08-29T18:16:33")
	require.True(t, ok)
	assert.Equal(t, 2026, got.Year())
}

func TestParseNvdTime_RFC3339StillWorks(t *testing.T) {
	got, ok := parseNvdTime("2026-08-29T18:16:33Z")
	require.True(t, ok)
	assert.Equal(t, 33, got.Second())
}

func TestParseNvdTime_Unparseable(t *testing.T) {
	for _, s := range []string{"", "nonsense", "29/08/2026"} {
		_, ok := parseNvdTime(s)
		assert.False(t, ok, "expected failure for %q", s)
	}
}

// ---------------------------------------------------------------------------
// trimReferences / flattenCveTags
// ---------------------------------------------------------------------------

func TestTrimReferences_DropsSourceKeepsTags(t *testing.T) {
	var refs []NvdReference
	require.NoError(t, json.Unmarshal([]byte(`[
		{"url": "https://example.test/a", "source": "psirt@adobe.com", "tags": ["Patch"]},
		{"url": "https://example.test/b", "source": "cve@mitre.org"}
	]`), &refs))
	out := trimReferences(refs)
	require.Len(t, out, 2)
	assert.Equal(t, "https://example.test/a", out[0].URL)
	assert.Equal(t, []string{"Patch"}, out[0].Tags)

	// `source` must not survive the round trip.
	encoded, err := json.Marshal(out)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "psirt@adobe.com")
}

func TestTrimReferences_SkipsEmptyURL(t *testing.T) {
	out := trimReferences([]NvdReference{{URL: ""}, {URL: "https://example.test/x"}})
	require.Len(t, out, 1)
	assert.Nil(t, trimReferences([]NvdReference{{URL: ""}}))
	assert.Nil(t, trimReferences(nil))
}

func TestFlattenCveTags_DedupesAcrossSources(t *testing.T) {
	out := flattenCveTags([]NvdCveTag{
		{SourceIdentifier: "cve@mitre.org", Tags: []string{"disputed"}},
		{SourceIdentifier: "psirt@vendor.test", Tags: []string{"disputed", "unsupported-when-assigned"}},
	})
	assert.Equal(t, []string{"disputed", "unsupported-when-assigned"}, out)
	assert.Nil(t, flattenCveTags(nil))
	assert.Nil(t, flattenCveTags([]NvdCveTag{{Tags: []string{}}}))
}
