package ingestor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/metrics"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/microcosm-cc/bluemonday"
	"github.com/mmcdole/gofeed"
)

type Client struct {
	db     *pgxpool.Pool
	policy *bluemonday.Policy
	pf     *gofeed.Parser
}

func New(db *pgxpool.Pool) *Client {
	pf := gofeed.NewParser()
	pf.UserAgent = "TigerFetch-Go/1.0"
	return &Client{
		db:     db,
		policy: bluemonday.UGCPolicy(),
		pf:     pf,
	}
}

func (c *Client) FetchAndSave(ctx context.Context, feedCfg config.Feed) (retErr error) {
	start := time.Now()
	defer func() {
		metrics.FeedFetchDuration.WithLabelValues(feedCfg.Name).Observe(time.Since(start).Seconds())
		if retErr != nil {
			metrics.FeedFetches.WithLabelValues(feedCfg.Name, "error").Inc()
		} else {
			metrics.FeedFetches.WithLabelValues(feedCfg.Name, "success").Inc()
			metrics.FeedLastSuccess.WithLabelValues(feedCfg.Name).Set(float64(time.Now().Unix()))
		}
	}()

	opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	slog.Debug("Fetching feed", "url", feedCfg.URL)

	httpStart := time.Now()
	feed, err := c.pf.ParseURLWithContext(feedCfg.URL, opCtx)
	metrics.UpstreamRequestDuration.WithLabelValues("feed").Observe(time.Since(httpStart).Seconds())
	if err != nil {
		return fmt.Errorf("failed to parse feed %s: %w", feedCfg.URL, err)
	}

	slog.Info("Fetched feed success", "title", feed.Title, "items", len(feed.Items), "url", feedCfg.URL)

	processed := 0
	failed := 0
	for _, item := range feed.Items {
		if err := c.processItem(opCtx, feedCfg, feed, item); err != nil {
			slog.Error("Failed to process item", "guid", item.GUID, "error", err)
			failed++
			continue
		}
		processed++
	}

	metrics.FeedItemsProcessed.WithLabelValues(feedCfg.Name).Add(float64(processed))
	metrics.FeedItemsFailed.WithLabelValues(feedCfg.Name).Add(float64(failed))

	slog.Info("Processed items", "count", processed, "feed", feedCfg.Name)

	return nil
}

func (c *Client) processItem(ctx context.Context, feedCfg config.Feed, feed *gofeed.Feed, item *gofeed.Item) error {
	// 1. Sanitize
	content := c.policy.Sanitize(item.Content)
	if content == "" {
		content = c.policy.Sanitize(item.Description)
	}
	summary := c.policy.Sanitize(item.Description)

	// Track empty content
	if content == "" && summary == "" {
		metrics.FeedItemsEmptyContent.WithLabelValues(feedCfg.Name).Inc()
	}

	// 2. Resolve fields
	guid := item.GUID
	if guid == "" {
		guid = item.Link
	}
	if guid == "" {
		return fmt.Errorf("item has no guid and no link")
	}

	published := time.Now()
	if item.PublishedParsed != nil {
		published = *item.PublishedParsed
	} else if item.UpdatedParsed != nil {
		published = *item.UpdatedParsed
	}

	updated := published
	if item.UpdatedParsed != nil {
		updated = *item.UpdatedParsed
	}

	author := ""
	if len(item.Authors) > 0 {
		author = item.Authors[0].Name
	}

	categories := item.Categories
	if categories == nil {
		categories = []string{}
	}

	feedTitle := feed.Title
	feedDesc := feed.Description
	feedLang := feed.Language

	tx, err := c.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 3. Archive Table (Insert if not exists)
	const archiveQuery = `
		INSERT INTO archive (
			guid, title, link, published, content, summary, author, categories,
			entry_updated, feed_url, feed_title, feed_description, feed_language,
			feed_updated, inserted_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, NOW()
		)
		ON CONFLICT (guid, feed_url) DO NOTHING
	`

	archiveResult, err := tx.Exec(ctx, archiveQuery,
		guid, item.Title, item.Link, published, content, summary, author, categories,
		updated, feedCfg.URL, feedTitle, feedDesc, feedLang,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to insert archive: %w", err)
	}

	if archiveResult.RowsAffected() > 0 {
		metrics.FeedItemsNew.WithLabelValues(feedCfg.Name).Inc()
	}

	// 4. Current Table (Upsert)
	const currentQuery = `
		INSERT INTO current (
			guid, title, link, published, content, summary, author, categories,
			entry_updated, feed_url, feed_title, feed_description, feed_language,
			feed_updated, inserted_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, NOW()
		)
		ON CONFLICT (guid, feed_url) DO UPDATE SET
			title = EXCLUDED.title,
			link = EXCLUDED.link,
			published = EXCLUDED.published,
			content = EXCLUDED.content,
			summary = EXCLUDED.summary,
			author = EXCLUDED.author,
			categories = EXCLUDED.categories,
			entry_updated = EXCLUDED.entry_updated,
			feed_url = EXCLUDED.feed_url,
			feed_title = EXCLUDED.feed_title,
			feed_description = EXCLUDED.feed_description,
			feed_updated = EXCLUDED.feed_updated
	`

	currentResult, err := tx.Exec(ctx, currentQuery,
		guid, item.Title, item.Link, published, content, summary, author, categories,
		updated, feedCfg.URL, feedTitle, feedDesc, feedLang,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to upsert current: %w", err)
	}

	// If archive was a no-op (already existed) but current did upsert, it's an update
	if archiveResult.RowsAffected() == 0 && currentResult.RowsAffected() > 0 {
		metrics.FeedItemsUpdated.WithLabelValues(feedCfg.Name).Inc()
	}

	return tx.Commit(ctx)
}
