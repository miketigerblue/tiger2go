package abusech

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseInt64(t *testing.T) {
	cases := []struct {
		in     string
		want   int64
		wantOK bool
	}{
		{"", 0, false},
		{"abc", 0, false},
		{"123", 123, true},
		{"  42  ", 42, true},
		{"-1", -1, true},
	}
	for _, tc := range cases {
		got, ok := parseInt64(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("parseInt64(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestParseInt(t *testing.T) {
	if parseInt("") != 0 {
		t.Errorf("empty should be 0")
	}
	if parseInt("garbage") != 0 {
		t.Errorf("garbage should be 0")
	}
	if parseInt(" 75 ") != 75 {
		t.Errorf("expected 75")
	}
}

func TestParseBoolish(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"0":     false,
		"false": false,
		"no":    false,
		"1":     true,
		"true":  true,
		"YES":   true,
	}
	for in, want := range cases {
		if got := parseBoolish(in); got != want {
			t.Errorf("parseBoolish(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormaliseTags(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{nil, []string{}},
		{[]string{"a", "b"}, []string{"a", "b"}},
		{[]string{"a", "", " ", "b"}, []string{"a", "b"}},
		{[]string{"  trim  ", "ok"}, []string{"trim", "ok"}},
	}
	for _, tc := range cases {
		got := normaliseTags(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("normaliseTags(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNilInt(t *testing.T) {
	if nilInt(0) != nil {
		t.Errorf("0 should be nil")
	}
	if v := nilInt(42); v != 42 {
		t.Errorf("expected 42, got %v", v)
	}
}

// TestThreatFoxResponse_Unmarshal pins the JSON shape the ingestor expects.
// Drift in field names is the single most common reason the upstream
// abuse.ch API breaks ingestion silently; catch it here.
func TestThreatFoxResponse_Unmarshal(t *testing.T) {
	const sample = `{
		"query_status": "ok",
		"data": [{
			"id": "1234567",
			"ioc": "1.2.3.4:443",
			"threat_type": "botnet_cc",
			"ioc_type": "ip:port",
			"malware": "win.lockbit",
			"malware_alias": "LockBit",
			"malware_printable": "LockBit",
			"malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit",
			"confidence_level": "75",
			"first_seen": "2026-05-15 12:00:00",
			"last_seen": "2026-05-16 12:00:00",
			"reporter": "anon",
			"reference": "https://example.com/report",
			"tags": ["c2", "lockbit"],
			"anonymous": "0"
		}]
	}`

	var got threatFoxResponse
	if err := json.Unmarshal([]byte(sample), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.QueryStatus != "ok" {
		t.Fatalf("query_status = %q", got.QueryStatus)
	}
	if len(got.Data) != 1 {
		t.Fatalf("expected 1 data entry, got %d", len(got.Data))
	}
	ioc := got.Data[0]
	if ioc.IocID != "1234567" {
		t.Errorf("ioc id = %q", ioc.IocID)
	}
	if ioc.IocType != "ip:port" {
		t.Errorf("ioc type = %q", ioc.IocType)
	}
	if !reflect.DeepEqual(ioc.Tags, []string{"c2", "lockbit"}) {
		t.Errorf("tags = %v", ioc.Tags)
	}
}
