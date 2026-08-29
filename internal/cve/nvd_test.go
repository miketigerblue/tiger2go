package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/db"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNvdRunner_Integration(t *testing.T) {
	databaseURL, ok := os.LookupEnv("DATABASE_URL")
	if !ok || databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ctx := context.Background()

	// Run migrations to set up database schema
	err := db.Migrate(databaseURL, "../../migrations")
	require.NoError(t, err, "failed to run migrations")

	pool, err := db.NewPool(ctx, databaseURL)
	require.NoError(t, err)
	defer pool.Close()

	// 1. Mock Server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"resultsPerPage": 1,
			"startIndex": 0,
			"totalResults": 1,
			"format": "NVD_CVE",
			"version": "2.0",
			"timestamp": "2023-01-01T00:00:00.000",
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-TEST-NVD-001",
						"lastModified": "2023-01-01T00:00:00.000",
						"metrics": {
							"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]
						}
					}
				}
			]
		}`))
	}))
	defer mockServer.Close()

	// 2. Setup Cursor
	// Set cursor to 60 days ago. Logic maxWindow=120 days.
	// So Start=Now-60d, End=Now.
	start := time.Now().Add(-60 * time.Hour * 24).Format(time.RFC3339)

	_, err = pool.Exec(ctx, "DELETE FROM ingest_state WHERE source = 'NVD'")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO ingest_state (source, cursor) VALUES ('NVD', $1)", start)
	require.NoError(t, err)

	cfg := config.NvdConfig{
		Enabled:  true,
		ApiKey:   "test-key",
		PageSize: 10,
		URL:      mockServer.URL, // Injected URL
	}

	// 3. Run
	runner := NewNvdRunner(pool, cfg)
	err = runner.Run(ctx)
	require.NoError(t, err)

	// 4. Verify DB
	var count int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM cve_enriched WHERE cve_id = 'CVE-TEST-NVD-001'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Clean up
	_, _ = pool.Exec(ctx, "DELETE FROM cve_enriched WHERE cve_id = 'CVE-TEST-NVD-001'")
}

func TestNvdItemRetainsDescriptionsAndWeaknesses(t *testing.T) {
	payload := []byte(`{
		"cve": {
			"id": "CVE-2026-99999",
			"lastModified": "2026-08-05T12:00:00.000",
			"metrics": {"cvssMetricV31": []},
			"descriptions": [
				{"lang": "en", "value": "An authentication bypass in ExampleD."},
				{"lang": "es", "value": "Una omisión de autenticación."}
			],
			"weaknesses": [
				{"source": "nvd@nist.gov", "type": "Primary",
				 "description": [{"lang": "en", "value": "CWE-287"}]}
			]
		}
	}`)
	var item NvdCveItem
	require.NoError(t, json.Unmarshal(payload, &item))

	item.Cve.Descriptions = englishOnly(item.Cve.Descriptions)
	out, err := json.Marshal(item.Cve)
	require.NoError(t, err)

	var roundTrip map[string]any
	require.NoError(t, json.Unmarshal(out, &roundTrip))
	descs := roundTrip["descriptions"].([]any)
	assert.Len(t, descs, 1, "non-English descriptions must be dropped")
	assert.Contains(t, descs[0].(map[string]any)["value"], "authentication bypass")
	weaknesses := roundTrip["weaknesses"].([]any)
	assert.Contains(t,
		weaknesses[0].(map[string]any)["description"].([]any)[0].(map[string]any)["value"],
		"CWE-287")
}

func TestEnglishOnlyFallsBackToFirst(t *testing.T) {
	descs := []NvdDescription{{Lang: "es", Value: "solo español"}}
	assert.Len(t, englishOnly(descs), 1)
	assert.Nil(t, englishOnly(nil))
}

// TestNvdRunner_WidenedCapture drives a realistic NVD 2.0 record all the
// way through saveBatch and asserts every column added by migration
// 20260829200000 lands. The payload deliberately carries only a v2 CVSS
// score, so it also covers the fallback that used to leave cvss_base
// NULL on 70,872 rows.
func TestNvdRunner_WidenedCapture(t *testing.T) {
	databaseURL, ok := os.LookupEnv("DATABASE_URL")
	if !ok || databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ctx := context.Background()
	require.NoError(t, db.Migrate(databaseURL, "../../migrations"))

	pool, err := db.NewPool(ctx, databaseURL)
	require.NoError(t, err)
	defer pool.Close()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
			"format": "NVD_CVE", "version": "2.0",
			"timestamp": "2026-08-29T00:00:00.000",
			"vulnerabilities": [{"cve": {
				"id": "CVE-TEST-NVD-002",
				"sourceIdentifier": "cve@mitre.org",
				"published": "2019-03-04T09:29:00.313",
				"lastModified": "2026-08-14T05:16:49.797",
				"vulnStatus": "Deferred",
				"cveTags": [{"sourceIdentifier": "cve@mitre.org", "tags": ["disputed"]}],
				"metrics": {
					"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}],
					"ssvcV203": [{"ssvcData": {"options": [
						{"exploitation": "active"}, {"automatable": "yes"},
						{"technicalImpact": "total"}]}}]
				},
				"descriptions": [{"lang": "en", "value": "Test record."}],
				"references": [
					{"url": "https://example.test/advisory", "source": "cve@mitre.org",
					 "tags": ["Vendor Advisory", "Patch"]},
					{"url": "https://example.test/exploit", "source": "cve@mitre.org"}
				]
			}}]
		}`))
	}))
	defer mockServer.Close()

	start := time.Now().Add(-60 * time.Hour * 24).Format(time.RFC3339)
	_, err = pool.Exec(ctx, "DELETE FROM ingest_state WHERE source = 'NVD'")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO ingest_state (source, cursor) VALUES ('NVD', $1)", start)
	require.NoError(t, err)

	runner := NewNvdRunner(pool, config.NvdConfig{
		Enabled: true, ApiKey: "test-key", PageSize: 10, URL: mockServer.URL,
	})
	require.NoError(t, runner.Run(ctx))
	defer func() {
		_, _ = pool.Exec(ctx, "DELETE FROM cve_enriched WHERE cve_id = 'CVE-TEST-NVD-002'")
	}()

	var (
		cvssBase                       *float64
		cvssVersion, vulnStatus, srcID string
		ssvcExpl, ssvcAuto, ssvcImpact string
		tags                           []string
		published, modified            time.Time
		refCount                       int
	)
	err = pool.QueryRow(ctx, `
		SELECT cvss_base, cvss_version, vuln_status, source_identifier,
		       ssvc_exploitation, ssvc_automatable, ssvc_technical_impact,
		       cve_tags, published, modified,
		       jsonb_array_length(json->'references')
		FROM cve_enriched WHERE cve_id = 'CVE-TEST-NVD-002'`).Scan(
		&cvssBase, &cvssVersion, &vulnStatus, &srcID,
		&ssvcExpl, &ssvcAuto, &ssvcImpact, &tags, &published, &modified, &refCount)
	require.NoError(t, err)

	// v2 fallback fires, and records which scale it used.
	require.NotNil(t, cvssBase)
	assert.InDelta(t, 7.5, *cvssBase, 0.001)
	assert.Equal(t, "2.0", cvssVersion)

	assert.Equal(t, "Deferred", vulnStatus)
	assert.Equal(t, "cve@mitre.org", srcID)
	assert.Equal(t, []string{"disputed"}, tags)
	assert.Equal(t, "active", ssvcExpl)
	assert.Equal(t, "yes", ssvcAuto)
	assert.Equal(t, "total", ssvcImpact)

	// The timestamp regression: NVD's naive format must parse, and
	// modified must be NVD's value rather than the ingest time.
	assert.Equal(t, "2019-03-04T09:29:00Z", published.UTC().Format(time.RFC3339))
	assert.Equal(t, "2026-08-14T05:16:49Z", modified.UTC().Format(time.RFC3339))

	// References captured, and `source` stripped from each.
	assert.Equal(t, 2, refCount)
	var refsJSON string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT (json->'references')::text FROM cve_enriched WHERE cve_id = 'CVE-TEST-NVD-002'`).Scan(&refsJSON))
	assert.Contains(t, refsJSON, "https://example.test/advisory")
	assert.Contains(t, refsJSON, "Vendor Advisory")
	assert.NotContains(t, refsJSON, "cve@mitre.org")
}
