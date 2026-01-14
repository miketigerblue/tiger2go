package ingestor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"tiger2go/internal/config"

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

func (c *Client) FetchAndSave(ctx context.Context, feedCfg config.Feed) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	slog.Debug("Fetching feed", "url", feedCfg.URL)
	feed, err := c.pf.ParseURLWithContext(feedCfg.URL, ctx)
	if err != nil {
		return fmt.Errorf("failed to parse feed %s: %w", feedCfg.URL, err)
	}

	slog.Info("Fetched feed success", "title", feed.Title, "items", len(feed.Items), "url", feedCfg.URL)

	count := 0
	for _, item := range feed.Items {
		if err := c.processItem(ctx, feedCfg, feed, item); err != nil {
			slog.Error("Failed to process item", "guid", item.GUID, "error", err)
			continue
		}
		count++
	}
	slog.Info("Processed items", "count", count, "feed", feedCfg.Name)

	return nil
}

func (c *Client) processItem(ctx context.Context, feedCfg config.Feed, feed *gofeed.Feed, item *gofeed.Item) error {
	// 1. Sanitize
	content := c.policy.Sanitize(item.Content)
	if content == "" {
		content = c.policy.Sanitize(item.Description)
	}
	summary := c.policy.Sanitize(item.Description)

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
		ON CONFLICT (guid) DO NOTHING
	`

	_, err = tx.Exec(ctx, archiveQuery,
		guid, item.Title, item.Link, published, content, summary, author, categories,
		updated, feedCfg.URL, feedTitle, feedDesc, feedLang,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to insert archive: %w", err)
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
		ON CONFLICT (guid) DO UPDATE SET
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

	_, err = tx.Exec(ctx, currentQuery,
		guid, item.Title, item.Link, published, content, summary, author, categories,
		updated, feedCfg.URL, feedTitle, feedDesc, feedLang,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to upsert current: %w", err)
	}

	return tx.Commit(ctx)
}
