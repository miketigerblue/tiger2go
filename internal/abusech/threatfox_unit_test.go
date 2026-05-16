package abusech

import (
	"encoding/json"
	"reflect"
	"testing"
)

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

// TestThreatFoxResponse_Unmarshal pins the JSON shape the ingestor expects.
// Field types are based on a live response captured 2026-05-16: `id` and
// `confidence_level` are numeric, `anonymous` is the string "0" / "1".
// Drift in field names/types is the single most common reason the upstream
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
			"confidence_level": 75,
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
	if ioc.ConfidenceLevel == nil || *ioc.ConfidenceLevel != 75 {
		t.Errorf("confidence_level = %v", ioc.ConfidenceLevel)
	}
	if !reflect.DeepEqual(ioc.Tags, []string{"c2", "lockbit"}) {
		t.Errorf("tags = %v", ioc.Tags)
	}
}
