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

// TestEpssRunner_Integration requires a running DB.
// It uses httptest to mock the upstream API.
func TestEpssRunner_Integration(t *testing.T) {
	databaseURL, ok := os.LookupEnv("DATABASE_URL")
	if !ok || databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ctx := context.Background()

	pool, err := db.NewPool(ctx, databaseURL)
	require.NoError(t, err)
	defer pool.Close()

	// 1. Mock Server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request query params
		offset := r.URL.Query().Get("offset")

		if offset == "0" {
			// First page
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"status": "OK",
				"total": 2,
				"offset": 0,
				"limit": 5000,
				"data": [
					{"cve": "CVE-TEST-0001", "epss": "0.99", "percentile": "0.99", "date": "2100-01-01"}
				]
			}`))
		} else {
			// Second page (finish)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"status": "OK",
				"total": 2,
				"offset": 1,
				"limit": 5000,
				"data": [
					{"cve": "CVE-TEST-0002", "epss": "0.11", "percentile": "0.11", "date": "2100-01-01"}
				]
			}`))
		}
	}))
	defer mockServer.Close()

	// 2. Config
	cfg := config.EpssConfig{
		Enabled:  true,
		URL:      mockServer.URL, // Point to mock
		PageSize: 1,              // Force pagination
	}

	// 3. Run
	runner := NewEpssRunner(pool, cfg)
	err = runner.Run(ctx)
	require.NoError(t, err)

	// 4. Verify DB
	var count int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM epss_daily WHERE as_of = '2100-01-01'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Cleanup
	_, _ = pool.Exec(ctx, "DELETE FROM epss_daily WHERE as_of = '2100-01-01'")
}
