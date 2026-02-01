package cve

import (
	"context"
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
