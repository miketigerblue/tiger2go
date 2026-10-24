package abusech

import (
	"encoding/json"
	"strings"
	"testing"
)

// sampleRecent is the shape /v1/urls/recent/ returns: a numeric id (the
// live API sent 3717331, not "3717331" — the first deploy of the JSON
// runner failed on exactly that), a "YYYY-MM-DD HH:MM:SS UTC" date_added,
// tags as an array or null, and no last_online field at all.
const sampleRecent = `{"query_status":"ok","urls":[
 {"id":3717331,"urlhaus_reference":"https://urlhaus.abuse.ch/url/3717331/","url":"http://203.0.113.9/bins/mozi.m",
  "url_status":"online","host":"203.0.113.9","date_added":"2026-10-24 07:51:04 UTC","threat":"malware_download",
  "blacklists":{"spamhaus_dbl":"not listed","surbl":"not listed"},"reporter":"abuse_ch","larted":"true",
  "takedown_time_seconds":null,"tags":["elf","Mozi"]},
 {"id":"3717330","urlhaus_reference":"https://urlhaus.abuse.ch/url/3717330/","url":"http://198.51.100.4/x.exe",
  "url_status":"offline","host":"198.51.100.4","date_added":"2026-10-24 07:50:59 UTC","threat":"malware_download",
  "blacklists":{},"reporter":"someone","larted":"false","takedown_time_seconds":"120","tags":null}
]}`

func TestParseUrlhausResponse(t *testing.T) {
	entries, err := parseUrlhausResponse(strings.NewReader(sampleRecent))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	e := entries[0]
	if e.ID != "3717331" || e.URL != "http://203.0.113.9/bins/mozi.m" || e.URLStatus != "online" {
		t.Fatalf("unexpected first entry: %+v", e)
	}
	if len(e.Tags) != 2 || e.Tags[1] != "Mozi" {
		t.Fatalf("tags not decoded: %v", e.Tags)
	}
	if entries[1].Tags != nil {
		t.Fatalf("null tags should decode to nil, got %v", entries[1].Tags)
	}
	if ts := parseTime(e.DateAdded); ts == nil || ts.Hour() != 7 || ts.Minute() != 51 {
		t.Fatalf("date_added did not parse: %q -> %v", e.DateAdded, ts)
	}
	if entries[1].LastOnline != "" || parseTime(entries[1].LastOnline) != nil {
		t.Fatal("absent last_online must stay empty / nil")
	}
}

func TestAsString(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"abc", "abc"}, {nil, ""}, {true, "true"}, {false, "false"},
		{float64(3717331), "3717331"}, {float64(2.5), "2.5"},
		{json.Number("3717331"), "3717331"},
	}
	for _, c := range cases {
		if got := asString(c.in); got != c.want {
			t.Errorf("asString(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEntryFromRaw_ToleratesScalarTypes(t *testing.T) {
	e, err := entryFromRaw(json.RawMessage(`{"id":42,"url":"http://x","url_status":null,"threat":"malware_download","reporter":"r","tags":["a",7,null],"larted":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "42" || e.URL != "http://x" || e.URLStatus != "" || len(e.Tags) != 2 || e.Tags[1] != "7" {
		t.Fatalf("unexpected: %+v", e)
	}
	if !strings.Contains(string(e.Raw), `"larted":true`) {
		t.Fatal("raw must keep the whole object")
	}
}

func TestParseUrlhausResponse_NoResultsIsEmpty(t *testing.T) {
	entries, err := parseUrlhausResponse(strings.NewReader(`{"query_status":"no_results","urls":null}`))
	if err != nil || len(entries) != 0 {
		t.Fatalf("no_results should be an empty page, got %v / %v", entries, err)
	}
}

func TestParseUrlhausResponse_OtherStatusIsAnError(t *testing.T) {
	for _, body := range []string{
		`{"query_status":"http_get_expected"}`,
		`{"query_status":"unauthorized"}`,
		`not json`,
	} {
		if _, err := parseUrlhausResponse(strings.NewReader(body)); err == nil {
			t.Fatalf("expected an error for %q", body)
		}
	}
}

func TestParseTime_UrlhausAPIFormat(t *testing.T) {
	got := parseTime("2026-10-24 07:51:04 UTC")
	if got == nil || got.Year() != 2026 || got.Month() != 10 || got.Day() != 24 || got.Hour() != 7 {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestParseTime_MalwareBazaarFormat(t *testing.T) {
	got := parseTime("2026-05-16 16:58:18")
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if got.Year() != 2026 || got.Month() != 5 || got.Day() != 16 {
		t.Fatalf("unexpected date: %v", got)
	}
}

// TestParseTime_ThreatFoxFormat pins the trailing-TZ-abbreviation shape that
// ThreatFox returns (e.g. "2026-05-16 18:46:11 UTC"). Without the MST layout,
// every first_seen / last_seen ingested NULL.
func TestParseTime_ThreatFoxFormat(t *testing.T) {
	got := parseTime("2026-05-16 18:46:11 UTC")
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if got.Hour() != 18 || got.Minute() != 46 || got.Second() != 11 {
		t.Fatalf("unexpected time-of-day: %v", got)
	}
	if got.Location().String() != "UTC" {
		t.Fatalf("expected UTC, got %s", got.Location())
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
