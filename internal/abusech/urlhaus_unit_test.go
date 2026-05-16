package abusech

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestStripComments(t *testing.T) {
	in := strings.NewReader("# banner\n# another comment\n\"1\",\"2026-01-01 00:00:00\",\"http://x\",\"online\",\"\",\"malware_download\",\"tag1,tag2\",\"link\",\"rep\"\n# trailing\n\"2\",\"2026-01-02\",\"http://y\",\"offline\",\"\",\"\",\"\",\"\",\"\"\n")
	out, err := io.ReadAll(stripComments(in))
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if strings.Contains(got, "#") {
		t.Fatalf("expected comments stripped, got:\n%s", got)
	}
	if !strings.Contains(got, "http://x") || !strings.Contains(got, "http://y") {
		t.Fatalf("expected data rows preserved, got:\n%s", got)
	}
}

func TestSplitTags(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b , c", []string{"a", "b", "c"}},
		{",,a,,b,,", []string{"a", "b"}},
		{"single", []string{"single"}},
	}
	for _, tc := range cases {
		got := splitTags(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitTags(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseTime_UrlhausFormat(t *testing.T) {
	got := parseTime("2026-05-16 16:58:18")
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if got.Year() != 2026 || got.Month() != 5 || got.Day() != 16 {
		t.Fatalf("unexpected date: %v", got)
	}
}

func TestParseTime_EmptyAndGarbage(t *testing.T) {
	if got := parseTime(""); got != nil {
		t.Fatalf("expected nil for empty, got %v", got)
	}
	if got := parseTime("not a time"); got != nil {
		t.Fatalf("expected nil for garbage, got %v", got)
	}
}

func TestNilEmpty(t *testing.T) {
	if nilEmpty("") != nil {
		t.Fatal("empty should be nil")
	}
	if v := nilEmpty("hello"); v != "hello" {
		t.Fatalf("expected hello, got %v", v)
	}
}
