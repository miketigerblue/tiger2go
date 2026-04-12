package ingestor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"tiger2go/internal/config"
	"tiger2go/internal/db"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRSSFeed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <link>https://example.com</link>
    <description>A test feed</description>
    <language>en</language>
    <item>
      <title>Test Article One</title>
      <link>https://example.com/article-1</link>
      <guid>test-guid-001</guid>
      <pubDate>Mon, 01 Jan 2099 00:00:00 GMT</pubDate>
      <description>Short summary of article one</description>
      <content:encoded><![CDATA[<p>Full content of article one</p>]]></content:encoded>
      <category>security</category>
      <category>testing</category>
    </item>
    <item>
      <title>Test Article Two</title>
      <link>https://example.com/article-2</link>
      <guid>test-guid-002</guid>
      <pubDate>Tue, 02 Jan 2099 00:00:00 GMT</pubDate>
      <description>Short summary of article two</description>
    </item>
  </channel>
</rss>`

const testRSSEmptyContent = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Empty Feed</title>
    <link>https://example.com</link>
    <item>
      <title>No Content Item</title>
      <link>https://example.com/empty</link>
      <guid>test-guid-empty</guid>
      <pubDate>Mon, 01 Jan 2099 00:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>`

const testRSSNoGUID = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Bad Feed</title>
    <item>
      <title>No GUID or Link</title>
    </item>
  </channel>
</rss>`

const testRSSXSS = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>XSS Feed</title>
    <item>
      <title>XSS Test</title>
      <link>https://example.com/xss</link>
      <guid>test-guid-xss</guid>
      <description><![CDATA[<script>alert('xss')</script><p>Legit description</p><img src=x onerror="alert(1)">]]></description>
    </item>
  </channel>
</rss>`

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	databaseURL, ok := os.LookupEnv("DATABASE_URL")
	if !ok || databaseURL == "" {
		// No DB available — tests will be skipped individually
		os.Exit(m.Run())
	}

	ctx := context.Background()

	// Run migrations once for all tests in this package
	if err := db.Migrate(databaseURL, "../../migrations"); err != nil {
		panic("failed to run migrations: " + err.Error())
	}

	pool, err := db.NewPool(ctx, databaseURL)
	if err != nil {
		panic("failed to create pool: " + err.Error())
	}
	testPool = pool

	code := m.Run()
	pool.Close()
	os.Exit(code)
}

func skipIfNoDB(t *testing.T) {
	t.Helper()
	if testPool == nil {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}
}

func TestFetchAndSave_Integration(t *testing.T) {
	skipIfNoDB(t)

	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testRSSFeed))
	}))
	defer mockServer.Close()

	feedCfg := config.Feed{
		Name:     "Test Feed",
		URL:      mockServer.URL,
		FeedType: "test",
		Tags:     []string{"test"},
	}

	// Clean up any prior test data
	_, _ = testPool.Exec(ctx, "DELETE FROM archive WHERE feed_url = $1", mockServer.URL)
	_, _ = testPool.Exec(ctx, "DELETE FROM current WHERE feed_url = $1", mockServer.URL)

	client := New(testPool)

	// First run: items should be new
	err := client.FetchAndSave(ctx, feedCfg)
	require.NoError(t, err)

	var archiveCount, currentCount int
	err = testPool.QueryRow(ctx, "SELECT count(*) FROM archive WHERE feed_url = $1", mockServer.URL).Scan(&archiveCount)
	require.NoError(t, err)
	assert.Equal(t, 2, archiveCount, "expected 2 items in archive")

	err = testPool.QueryRow(ctx, "SELECT count(*) FROM current WHERE feed_url = $1", mockServer.URL).Scan(&currentCount)
	require.NoError(t, err)
	assert.Equal(t, 2, currentCount, "expected 2 items in current")

	// Verify content was stored
	var title, summary string
	err = testPool.QueryRow(ctx, "SELECT title, summary FROM archive WHERE guid = 'test-guid-001' AND feed_url = $1", mockServer.URL).Scan(&title, &summary)
	require.NoError(t, err)
	assert.Equal(t, "Test Article One", title)
	assert.Equal(t, "Short summary of article one", summary)

	// Second run: should be idempotent (no new archive rows)
	err = client.FetchAndSave(ctx, feedCfg)
	require.NoError(t, err)

	err = testPool.QueryRow(ctx, "SELECT count(*) FROM archive WHERE feed_url = $1", mockServer.URL).Scan(&archiveCount)
	require.NoError(t, err)
	assert.Equal(t, 2, archiveCount, "archive count should not change on re-ingest")

	// Clean up
	_, _ = testPool.Exec(ctx, "DELETE FROM archive WHERE feed_url = $1", mockServer.URL)
	_, _ = testPool.Exec(ctx, "DELETE FROM current WHERE feed_url = $1", mockServer.URL)
}

func TestFetchAndSave_EmptyContent(t *testing.T) {
	skipIfNoDB(t)

	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		_, _ = w.Write([]byte(testRSSEmptyContent))
	}))
	defer mockServer.Close()

	feedCfg := config.Feed{
		Name: "Empty Content Feed",
		URL:  mockServer.URL,
	}

	_, _ = testPool.Exec(ctx, "DELETE FROM archive WHERE feed_url = $1", mockServer.URL)
	_, _ = testPool.Exec(ctx, "DELETE FROM current WHERE feed_url = $1", mockServer.URL)

	client := New(testPool)
	err := client.FetchAndSave(ctx, feedCfg)
	require.NoError(t, err)

	// Item should still be saved even with empty content
	var count int
	err = testPool.QueryRow(ctx, "SELECT count(*) FROM archive WHERE feed_url = $1", mockServer.URL).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	_, _ = testPool.Exec(ctx, "DELETE FROM archive WHERE feed_url = $1", mockServer.URL)
	_, _ = testPool.Exec(ctx, "DELETE FROM current WHERE feed_url = $1", mockServer.URL)
}

func TestFetchAndSave_NoGUID(t *testing.T) {
	skipIfNoDB(t)

	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		_, _ = w.Write([]byte(testRSSNoGUID))
	}))
	defer mockServer.Close()

	feedCfg := config.Feed{
		Name: "Bad Feed",
		URL:  mockServer.URL,
	}

	client := New(testPool)
	// Should not error at the FetchAndSave level — bad items are skipped
	err := client.FetchAndSave(ctx, feedCfg)
	require.NoError(t, err)

	// Nothing should be in the DB
	var count int
	err = testPool.QueryRow(ctx, "SELECT count(*) FROM archive WHERE feed_url = $1", mockServer.URL).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestFetchAndSave_XSSSanitization(t *testing.T) {
	skipIfNoDB(t)

	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		_, _ = w.Write([]byte(testRSSXSS))
	}))
	defer mockServer.Close()

	feedCfg := config.Feed{
		Name: "XSS Feed",
		URL:  mockServer.URL,
	}

	_, _ = testPool.Exec(ctx, "DELETE FROM archive WHERE feed_url = $1", mockServer.URL)
	_, _ = testPool.Exec(ctx, "DELETE FROM current WHERE feed_url = $1", mockServer.URL)

	client := New(testPool)
	err := client.FetchAndSave(ctx, feedCfg)
	require.NoError(t, err)

	// Script tags and event handlers should be stripped by bluemonday
	var summary string
	err = testPool.QueryRow(ctx, "SELECT summary FROM archive WHERE guid = 'test-guid-xss' AND feed_url = $1", mockServer.URL).Scan(&summary)
	require.NoError(t, err)
	assert.NotContains(t, summary, "<script>", "script tags must be stripped")
	assert.NotContains(t, summary, "onerror", "event handlers must be stripped")
	assert.NotContains(t, summary, "alert(", "JS payloads must be stripped")
	assert.Contains(t, summary, "Legit description", "safe content must be preserved")

	_, _ = testPool.Exec(ctx, "DELETE FROM archive WHERE feed_url = $1", mockServer.URL)
	_, _ = testPool.Exec(ctx, "DELETE FROM current WHERE feed_url = $1", mockServer.URL)
}

func TestFetchAndSave_HTTPError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	skipIfNoDB(t)

	ctx := context.Background()

	feedCfg := config.Feed{
		Name: "Broken Feed",
		URL:  mockServer.URL,
	}

	client := New(testPool)
	err := client.FetchAndSave(ctx, feedCfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse feed")
}
