package cve

import (
	"encoding/json"
	"testing"
)

// CPE parsing decides which customer sees which CVE. A quiet mistake
// here does not error — it silently under- or over-reports an estate.

func TestParseCpe23(t *testing.T) {
	cases := []struct {
		name                                string
		in                                  string
		part, vendor, product, version, upd string
		ok                                  bool
	}{
		{
			name: "typical application",
			in:   "cpe:2.3:a:fortinet:fortios:7.2.4:*:*:*:*:*:*:*",
			part: "a", vendor: "fortinet", product: "fortios", version: "7.2.4", upd: "*", ok: true,
		},
		{
			name: "wildcard version, range lives on the node",
			in:   "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*",
			part: "o", vendor: "cisco", product: "ios_xe", version: "*", upd: "*", ok: true,
		},
		{
			name: "hardware appliance",
			in:   "cpe:2.3:h:sonicwall:sma_1000:-:*:*:*:*:*:*:*",
			part: "h", vendor: "sonicwall", product: "sma_1000", version: "-", upd: "*", ok: true,
		},
		{
			// Escaped colons are real: several vendors ship them in
			// version strings. Splitting naively shifts every field
			// left and files the CVE under the wrong product.
			name: "escaped colon inside a component",
			in:   `cpe:2.3:a:acme:weird\:product:1.0:*:*:*:*:*:*:*`,
			part: "a", vendor: "acme", product: `weird\:product`, version: "1.0", upd: "*", ok: true,
		},
		{name: "CPE 2.2 URI is refused", in: "cpe:/a:fortinet:fortios:7.2.4", ok: false},
		{name: "empty", in: "", ok: false},
		{name: "truncated", in: "cpe:2.3:a:fortinet", ok: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			part, vendor, product, version, upd, ok := parseCpe23(c.in)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !c.ok {
				return
			}
			if part != c.part || vendor != c.vendor || product != c.product ||
				version != c.version || upd != c.upd {
				t.Fatalf("got %q/%q/%q/%q/%q, want %q/%q/%q/%q/%q",
					part, vendor, product, version, upd,
					c.part, c.vendor, c.product, c.version, c.upd)
			}
		})
	}
}

func TestFlattenCpe(t *testing.T) {
	raw := `[
	  {"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
	    {"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
	     "matchCriteriaId":"AAA","versionStartIncluding":"7.0.0","versionEndExcluding":"7.2.5"},
	    {"vulnerable":false,"criteria":"cpe:2.3:h:fortinet:fortigate_100f:-:*:*:*:*:*:*:*"}
	  ]}]},
	  {"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
	    {"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
	     "matchCriteriaId":"AAA","versionStartIncluding":"7.0.0","versionEndExcluding":"7.2.5"}
	  ]}]},
	  {"nodes":[{"operator":"OR","negate":true,"cpeMatch":[
	    {"vulnerable":true,"criteria":"cpe:2.3:a:acme:nope:1.0:*:*:*:*:*:*:*"}
	  ]}]}
	]`
	var configs []NvdConfiguration
	if err := json.Unmarshal([]byte(raw), &configs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rows := flattenCpe(configs)

	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.vendor != "fortinet" || r.product != "fortios" || r.part != "o" {
		t.Fatalf("wrong product: %+v", r)
	}
	if r.startIncl != "7.0.0" || r.endExcl != "7.2.5" {
		t.Fatalf("range lost: %+v", r)
	}
	// The hardware entry was vulnerable:false — it describes what the
	// vulnerable OS runs on. Claiming it would tell a customer their
	// appliance is vulnerable when the advisory says otherwise.
	// The duplicate node collapsed. The negated node was skipped.
}

func TestFlattenCpeEmpty(t *testing.T) {
	if rows := flattenCpe(nil); len(rows) != 0 {
		t.Fatalf("nil configurations produced %d rows", len(rows))
	}
}
