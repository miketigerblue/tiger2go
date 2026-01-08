package feeds

import (
	"testing"
	"time"
)

func TestExtractCVEIDs(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		expected []string
	}{
		{
			name:     "Single CVE",
			text:     "This advisory addresses CVE-2024-1234",
			expected: []string{"CVE-2024-1234"},
		},
		{
			name:     "Multiple CVEs",
			text:     "Fixed CVE-2024-1234 and CVE-2023-5678",
			expected: []string{"CVE-2024-1234", "CVE-2023-5678"},
		},
		{
			name:     "Duplicate CVEs",
			text:     "CVE-2024-1234 is mentioned. Also CVE-2024-1234 again.",
			expected: []string{"CVE-2024-1234"},
		},
		{
			name:     "No CVEs",
			text:     "This text has no CVE identifiers",
			expected: []string{},
		},
		{
			name:     "CVE with more than 4 digits",
			text:     "Security issue CVE-2024-12345",
			expected: []string{"CVE-2024-12345"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCVEIDs(tt.text)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d CVEs, got %d", len(tt.expected), len(result))
				return
			}
			for i, cve := range result {
				if cve != tt.expected[i] {
					t.Errorf("Expected CVE %s, got %s", tt.expected[i], cve)
				}
			}
		})
	}
}

func TestParseRSS(t *testing.T) {
	rssData := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Security Advisories</title>
    <description>Latest security advisories</description>
    <link>https://example.com</link>
    <item>
      <title>Security Advisory - CVE-2024-1234</title>
      <link>https://example.com/advisory/1</link>
      <description>Critical vulnerability CVE-2024-1234 found in software X</description>
      <pubDate>Mon, 08 Jan 2024 12:00:00 +0000</pubDate>
      <guid>advisory-1</guid>
    </item>
  </channel>
</rss>`)

	parser := NewFeedParser(30 * time.Second)
	advisories, err := parser.parseRSS(rssData, "TestFeed")
	if err != nil {
		t.Fatalf("Failed to parse RSS: %v", err)
	}

	if len(advisories) != 1 {
		t.Fatalf("Expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Title != "Security Advisory - CVE-2024-1234" {
		t.Errorf("Expected title 'Security Advisory - CVE-2024-1234', got '%s'", adv.Title)
	}
	if adv.Source != "TestFeed" {
		t.Errorf("Expected source 'TestFeed', got '%s'", adv.Source)
	}
	if len(adv.CVEIDs) != 1 || adv.CVEIDs[0] != "CVE-2024-1234" {
		t.Errorf("Expected CVE-2024-1234, got %v", adv.CVEIDs)
	}
}

func TestParseAtom(t *testing.T) {
	atomData := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Security Advisories</title>
  <link href="https://example.com"/>
  <entry>
    <title>Security Advisory - CVE-2024-5678</title>
    <link href="https://example.com/advisory/2" rel="alternate"/>
    <id>advisory-2</id>
    <updated>2024-01-08T12:00:00Z</updated>
    <summary>Important vulnerability CVE-2024-5678 discovered</summary>
  </entry>
</feed>`)

	parser := NewFeedParser(30 * time.Second)
	advisories, err := parser.parseAtom(atomData, "TestFeed")
	if err != nil {
		t.Fatalf("Failed to parse Atom: %v", err)
	}

	if len(advisories) != 1 {
		t.Fatalf("Expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Title != "Security Advisory - CVE-2024-5678" {
		t.Errorf("Expected title 'Security Advisory - CVE-2024-5678', got '%s'", adv.Title)
	}
	if adv.Source != "TestFeed" {
		t.Errorf("Expected source 'TestFeed', got '%s'", adv.Source)
	}
	if len(adv.CVEIDs) != 1 || adv.CVEIDs[0] != "CVE-2024-5678" {
		t.Errorf("Expected CVE-2024-5678, got %v", adv.CVEIDs)
	}
}

func TestNewFeedParser(t *testing.T) {
	timeout := 30 * time.Second
	parser := NewFeedParser(timeout)
	if parser == nil {
		t.Fatal("Expected non-nil parser")
	}
	if parser.timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, parser.timeout)
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		name      string
		timeStr   string
		shouldErr bool
	}{
		{
			name:      "RFC1123Z",
			timeStr:   "Mon, 08 Jan 2024 12:00:00 +0000",
			shouldErr: false,
		},
		{
			name:      "RFC3339",
			timeStr:   "2024-01-08T12:00:00Z",
			shouldErr: false,
		},
		{
			name:      "Invalid format",
			timeStr:   "not a valid time",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTime(tt.timeStr)
			if tt.shouldErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}
