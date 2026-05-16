package ghsa

import (
	"reflect"
	"testing"
)

func TestParseNextLink_Present(t *testing.T) {
	link := `<https://api.github.com/advisories?page=1&per_page=100>; rel="prev", <https://api.github.com/advisories?page=3&per_page=100>; rel="next"`
	got := parseNextLink(link)
	want := "https://api.github.com/advisories?page=3&per_page=100"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseNextLink_Absent(t *testing.T) {
	link := `<https://api.github.com/advisories?page=2>; rel="prev"`
	if got := parseNextLink(link); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestParseNextLink_Empty(t *testing.T) {
	if got := parseNextLink(""); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestExtractCWEs(t *testing.T) {
	cwes := []CWE{
		{CweID: "CWE-79", Name: "XSS"},
		{CweID: "", Name: "skipped"},
		{CweID: "CWE-89", Name: "SQLi"},
	}
	got := extractCWEs(cwes)
	want := []string{"CWE-79", "CWE-89"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractEcosystems_Dedupes(t *testing.T) {
	vs := []Vulnerability{
		{Package: Package{Ecosystem: "npm", Name: "foo"}},
		{Package: Package{Ecosystem: "pypi", Name: "bar"}},
		{Package: Package{Ecosystem: "npm", Name: "baz"}}, // duplicate ecosystem
		{Package: Package{Ecosystem: "", Name: "skipped"}},
	}
	got := extractEcosystems(vs)
	want := []string{"npm", "pypi"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractPackageNames_Dedupes(t *testing.T) {
	vs := []Vulnerability{
		{Package: Package{Ecosystem: "npm", Name: "foo"}},
		{Package: Package{Ecosystem: "npm", Name: "bar"}},
		{Package: Package{Ecosystem: "pypi", Name: "foo"}}, // duplicate name
		{Package: Package{Ecosystem: "npm", Name: ""}},
	}
	got := extractPackageNames(vs)
	want := []string{"foo", "bar"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseTime_Various(t *testing.T) {
	if got := parseTime("2024-01-03T23:23:36Z"); got == nil || got.Year() != 2024 {
		t.Fatalf("RFC3339 parse failed: %v", got)
	}
	if got := parseTime("2024-01-03T23:23:36.123456Z"); got == nil || got.Year() != 2024 {
		t.Fatalf("RFC3339Nano parse failed: %v", got)
	}
	if got := parseTime(""); got != nil {
		t.Fatalf("expected nil for empty, got %v", got)
	}
	if got := parseTime("garbage"); got != nil {
		t.Fatalf("expected nil for garbage, got %v", got)
	}
}

func TestNilEmpty(t *testing.T) {
	if nilEmpty("") != nil {
		t.Fatal("empty string should be nil")
	}
	if v := nilEmpty("hello"); v != "hello" {
		t.Fatalf("expected hello, got %v", v)
	}
}
