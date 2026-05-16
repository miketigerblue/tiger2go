package msf

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestExtractCves_FromMixedRefs(t *testing.T) {
	refs := []string{
		"CVE-2024-1234",
		"OSVDB-12345",
		"URL-https://example.com",
		"EDB-50000",
		"cve-2023-9999", // lowercase should be normalised
		"CVE-2024-1234", // duplicate
	}
	got := extractCves(refs)
	sort.Strings(got)
	want := []string{"CVE-2023-9999", "CVE-2024-1234"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExtractCves_NoCves(t *testing.T) {
	refs := []string{"OSVDB-1", "URL-https://x"}
	if got := extractCves(refs); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestSplitPlatform(t *testing.T) {
	cases := map[string][]string{
		"":              {},
		"linux":         {"linux"},
		"linux,windows": {"linux", "windows"},
		" Linux , OSX ": {"linux", "osx"},
		",,,linux,,,":   {"linux"},
	}
	for in, want := range cases {
		got := splitPlatform(in)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("splitPlatform(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseDate(t *testing.T) {
	got := parseDate("2024-01-15")
	if got == nil || got.Year() != 2024 || got.Month() != time.January || got.Day() != 15 {
		t.Fatalf("unexpected: %v", got)
	}
	if got := parseDate(""); got != nil {
		t.Fatalf("expected nil for empty, got %v", got)
	}
	if got := parseDate("not a date"); got != nil {
		t.Fatalf("expected nil for garbage, got %v", got)
	}
}

func TestSanitizeAll(t *testing.T) {
	in := []string{"  alice  ", "", "bob\x00", "  "}
	want := []string{"alice", "bob"}
	got := sanitizeAll(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestStripNUL(t *testing.T) {
	if got := stripNUL("hello\x00world"); got != "helloworld" {
		t.Fatalf("got %q", got)
	}
	// Pure ASCII pass-through (no allocation)
	if got := stripNUL("plain"); got != "plain" {
		t.Fatalf("got %q", got)
	}
}

func TestRankLabels_KnownValues(t *testing.T) {
	cases := map[int]string{
		0:   "manual",
		100: "low",
		200: "average",
		300: "normal",
		400: "good",
		500: "great",
		600: "excellent",
	}
	for r, want := range cases {
		if got := rankLabels[r]; got != want {
			t.Errorf("rankLabels[%d] = %q, want %q", r, got, want)
		}
	}
	if got := rankLabels[42]; got != "" {
		t.Errorf("unknown rank should return empty, got %q", got)
	}
}
