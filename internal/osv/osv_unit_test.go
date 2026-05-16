package osv

import (
	"reflect"
	"testing"
)

func TestExtractPackageNames_DeduplicatesAndPreservesOrder(t *testing.T) {
	v := Vulnerability{
		Affected: []Affected{
			{Package: Package{Name: "numpy", Ecosystem: "PyPI"}},
			{Package: Package{Name: "scipy", Ecosystem: "PyPI"}},
			{Package: Package{Name: "numpy", Ecosystem: "PyPI"}}, // duplicate
			{Package: Package{Name: "", Ecosystem: "PyPI"}},      // skipped
		},
	}
	got := extractPackageNames(v)
	want := []string{"numpy", "scipy"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractPackageNames_Empty(t *testing.T) {
	if got := extractPackageNames(Vulnerability{}); len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

func TestExtractCvssV3_VectorForm(t *testing.T) {
	sev := []Severity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8"},
	}
	got := extractCvssV3(sev)
	if got == nil || *got != 9.8 {
		t.Fatalf("expected 9.8, got %v", got)
	}
}

func TestExtractCvssV3_NumericForm(t *testing.T) {
	sev := []Severity{
		{Type: "CVSS_V3", Score: "7.5"},
	}
	got := extractCvssV3(sev)
	if got == nil || *got != 7.5 {
		t.Fatalf("expected 7.5, got %v", got)
	}
}

func TestExtractCvssV3_PrefersFirstV3(t *testing.T) {
	sev := []Severity{
		{Type: "CVSS_V2", Score: "5.0"},
		{Type: "CVSS_V3", Score: "8.1"},
		{Type: "CVSS_V3", Score: "1.0"}, // second V3 ignored
	}
	got := extractCvssV3(sev)
	if got == nil || *got != 8.1 {
		t.Fatalf("expected 8.1, got %v", got)
	}
}

func TestExtractCvssV3_NoneFound(t *testing.T) {
	sev := []Severity{
		{Type: "CVSS_V2", Score: "5.0"},
	}
	if got := extractCvssV3(sev); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestParseTime_RFC3339Nano(t *testing.T) {
	got := parseTime("2024-01-03T23:23:36.586611Z")
	if got == nil {
		t.Fatal("expected non-nil time")
	}
	if got.Year() != 2024 || got.Month() != 1 {
		t.Fatalf("unexpected time: %v", got)
	}
}

func TestParseTime_Empty(t *testing.T) {
	if got := parseTime(""); got != nil {
		t.Fatalf("expected nil for empty string, got %v", got)
	}
}

func TestParseTime_Garbage(t *testing.T) {
	if got := parseTime("not a date"); got != nil {
		t.Fatalf("expected nil for garbage input, got %v", got)
	}
}
