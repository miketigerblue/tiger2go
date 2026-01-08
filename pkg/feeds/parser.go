package feeds

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/miketigerblue/tiger2go/pkg/models"
)

// FeedParser handles parsing RSS/Atom feeds
type FeedParser struct {
	client  *http.Client
	timeout time.Duration
}

// NewFeedParser creates a new feed parser
func NewFeedParser(timeout time.Duration) *FeedParser {
	return &FeedParser{
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
	}
}

// RSS Feed structures
type RSSFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel Channel  `xml:"channel"`
}

type Channel struct {
	Title       string    `xml:"title"`
	Description string    `xml:"description"`
	Link        string    `xml:"link"`
	Items       []RSSItem `xml:"item"`
}

type RSSItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	GUID        string `xml:"guid"`
}

// Atom Feed structures
type AtomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Title   string      `xml:"title"`
	Link    []AtomLink  `xml:"link"`
	Entries []AtomEntry `xml:"entry"`
}

type AtomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

type AtomEntry struct {
	Title   string     `xml:"title"`
	Link    []AtomLink `xml:"link"`
	Summary string     `xml:"summary"`
	Content string     `xml:"content"`
	Updated string     `xml:"updated"`
	ID      string     `xml:"id"`
}

// FetchFeed fetches and parses a feed from the given URL
func (fp *FeedParser) FetchFeed(ctx context.Context, feedURL, source string) ([]models.Advisory, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := fp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Try parsing as RSS first
	advisories, err := fp.parseRSS(body, source)
	if err == nil {
		return advisories, nil
	}

	// Try parsing as Atom
	advisories, err = fp.parseAtom(body, source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse as RSS or Atom: %w", err)
	}

	return advisories, nil
}

func (fp *FeedParser) parseRSS(data []byte, source string) ([]models.Advisory, error) {
	var feed RSSFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, err
	}

	advisories := make([]models.Advisory, 0, len(feed.Channel.Items))
	for _, item := range feed.Channel.Items {
		advisory := models.Advisory{
			ID:          item.GUID,
			Title:       item.Title,
			Description: item.Description,
			Link:        item.Link,
			Source:      source,
			CVEIDs:      extractCVEIDs(item.Title + " " + item.Description),
		}

		if item.PubDate != "" {
			published, err := parseTime(item.PubDate)
			if err == nil {
				advisory.Published = published
			}
		}

		if advisory.ID == "" {
			advisory.ID = item.Link
		}

		advisories = append(advisories, advisory)
	}

	return advisories, nil
}

func (fp *FeedParser) parseAtom(data []byte, source string) ([]models.Advisory, error) {
	var feed AtomFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, err
	}

	advisories := make([]models.Advisory, 0, len(feed.Entries))
	for _, entry := range feed.Entries {
		var link string
		for _, l := range entry.Link {
			if l.Rel == "alternate" || l.Rel == "" {
				link = l.Href
				break
			}
		}

		content := entry.Summary
		if entry.Content != "" {
			content = entry.Content
		}

		advisory := models.Advisory{
			ID:          entry.ID,
			Title:       entry.Title,
			Description: content,
			Link:        link,
			Source:      source,
			CVEIDs:      extractCVEIDs(entry.Title + " " + content),
		}

		if entry.Updated != "" {
			published, err := parseTime(entry.Updated)
			if err == nil {
				advisory.Published = published
			}
		}

		advisories = append(advisories, advisory)
	}

	return advisories, nil
}

// extractCVEIDs extracts CVE IDs from text using regex
func extractCVEIDs(text string) []string {
	re := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	matches := re.FindAllString(text, -1)
	
	// Remove duplicates
	seen := make(map[string]bool)
	var unique []string
	for _, match := range matches {
		if !seen[match] {
			seen[match] = true
			unique = append(unique, match)
		}
	}
	
	return unique
}

// parseTime attempts to parse time in various formats
func parseTime(timeStr string) (time.Time, error) {
	formats := []string{
		time.RFC1123Z,
		time.RFC1123,
		time.RFC3339,
		time.RFC822Z,
		time.RFC822,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time: %s", timeStr)
}
