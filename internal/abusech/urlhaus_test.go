package abusech

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

// TestUrlhausRunner_Integration requires a running DB. The fake API checks
// the Auth-Key the way abuse.ch does (401 without it) and serves the
// sample page; the runner must upsert both rows and keep a last_online an
// earlier load stored.
func TestUrlhausRunner_Integration(t *testing.T) {
	databaseURL, ok := os.LookupEnv("DATABASE_URL")
	if !ok || databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	require.NoError(t, db.Migrate(databaseURL, "../../migrations"))
	pool, err := db.NewPool(ctx, databaseURL)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cleanup := func() { _, _ = pool.Exec(ctx, "DELETE FROM urlhaus_urls WHERE id IN ('3717331','3717330')") }
	cleanup()
	t.Cleanup(cleanup)

	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Auth-Key")
		if gotKey == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(sampleRecent))
	}))
	defer srv.Close()

	// A prior load knew when this URL was last online; /recent/ does not say.
	_, err = pool.Exec(ctx, `INSERT INTO urlhaus_urls (id, url, url_status, raw, last_online)
		VALUES ('3717331', 'http://203.0.113.9/bins/mozi.m', 'offline', '{}', '2026-10-23 12:00:00+00')`)
	require.NoError(t, err)

	cfg := config.UrlhausConfig{Enabled: true, URL: srv.URL}

	t.Run("no key is a loud error, not a skip", func(t *testing.T) {
		err := NewUrlhausRunner(pool, cfg, "").Run(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ABUSECH_API_KEY")
	})

	t.Run("upserts the page with the key", func(t *testing.T) {
		require.NoError(t, NewUrlhausRunner(pool, cfg, "test-key").Run(ctx))
		assert.Equal(t, "test-key", gotKey)

		var status, threat, link string
		var tags []string
		var lastOnline *string
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT url_status, threat, urlhaus_link, tags, last_online::text FROM urlhaus_urls WHERE id = '3717331'").
			Scan(&status, &threat, &link, &tags, &lastOnline))
		assert.Equal(t, "online", status, "status changed offline -> online")
		assert.Equal(t, "malware_download", threat)
		assert.Equal(t, "https://urlhaus.abuse.ch/url/3717331/", link)
		assert.Equal(t, []string{"elf", "Mozi"}, tags)
		require.NotNil(t, lastOnline)
		assert.Contains(t, *lastOnline, "2026-10-23 12:00:00", "last_online kept when the page omits it")

		var n int
		require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM urlhaus_urls WHERE id IN ('3717331','3717330')").Scan(&n))
		assert.Equal(t, 2, n)
		var untagged []string
		require.NoError(t, pool.QueryRow(ctx, "SELECT tags FROM urlhaus_urls WHERE id = '3717330'").Scan(&untagged))
		assert.Equal(t, []string{}, untagged, "null tags stored as an empty array")
	})
}
