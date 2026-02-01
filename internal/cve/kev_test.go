package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"tiger2go/internal/config"
	"tiger2go/internal/db"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKevRunner_Integration(t *testing.T) {
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
			"catalogVersion": "2099.01.01",
			"dateReleased": "2099-01-01T00:00:00Z",
			"count": 1,
			"vulnerabilities": [
				{
					"cveID": "CVE-TEST-KEV-001",
					"vendorProject": "Test",
					"product": "Test",
					"vulnerabilityName": "Test Vuln",
					"dateAdded": "2099-01-01",
					"shortDescription": "Desc",
					"requiredAction": "Patch",
					"dueDate": "2099-02-01",
					"notes": ""
				}
			]
		}`))
	}))
	defer mockServer.Close()

	// 2. Clear KEV State
	_, err = pool.Exec(ctx, "DELETE FROM ingest_state WHERE source = 'CISA-KEV'")
	require.NoError(t, err)

	cfg := config.KevConfig{
		Enabled: true,
		URL:     mockServer.URL,
	}

	// 3. Run
	runner := NewKevRunner(pool, cfg)
	err = runner.Run(ctx)
	require.NoError(t, err)

	// 4. Verify DB
	var count int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM cve_enriched WHERE cve_id = 'CVE-TEST-KEV-001' AND source = 'CISA-KEV'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// 5. Verify State
	var cursor string
	err = pool.QueryRow(ctx, "SELECT cursor FROM ingest_state WHERE source = 'CISA-KEV'").Scan(&cursor)
	require.NoError(t, err)
	// Our code normalizes to RFC3339 if parseable
	expected := "2099-01-01T00:00:00Z"
	assert.Equal(t, expected, cursor)

	// Clean up
	_, _ = pool.Exec(ctx, "DELETE FROM cve_enriched WHERE cve_id = 'CVE-TEST-KEV-001'")
}
