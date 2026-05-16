package nuclei

import (
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestStripLeadingDir(t *testing.T) {
	cases := map[string]string{
		"nuclei-templates-main/http/cves/2024/CVE-2024-1.yaml": "http/cves/2024/CVE-2024-1.yaml",
		"prefix/file.yaml": "file.yaml",
		"no-slash-here":    "no-slash-here",
	}
	for in, want := range cases {
		if got := stripLeadingDir(in); got != want {
			t.Errorf("stripLeadingDir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchesSubdirs(t *testing.T) {
	subs := []string{"http/cves/", "dns/", "javascript/cves/"}
	cases := map[string]bool{
		"http/cves/2024/CVE-2024-1.yaml": true,
		"dns/foo.yaml":                   true,
		"javascript/cves/x.yaml":         true,
		"misc/other.yaml":                false,
		"http/vulnerabilities/x.yaml":    false,
	}
	for in, want := range cases {
		if got := matchesSubdirs(in, subs); got != want {
			t.Errorf("matchesSubdirs(%q) = %v, want %v", in, got, want)
		}
	}
}

// Helper: build a yaml.Node by unmarshaling a snippet.
func mkNode(t *testing.T, src string) yaml.Node {
	t.Helper()
	var root struct {
		Field yaml.Node `yaml:"field"`
	}
	if err := yaml.Unmarshal([]byte("field: "+src+"\n"), &root); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	return root.Field
}

func TestFlattenStringNode_ScalarCommaList(t *testing.T) {
	n := mkNode(t, `"cve,2024,oast"`)
	got := flattenStringNode(n)
	want := []string{"cve", "2024", "oast"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestFlattenStringNode_Sequence(t *testing.T) {
	n := mkNode(t, "[\"alice\",\"bob\"]")
	got := flattenStringNode(n)
	want := []string{"alice", "bob"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestFlattenStringNode_Empty(t *testing.T) {
	if got := flattenStringNode(yaml.Node{}); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestExtractCves_FromIdAndPath(t *testing.T) {
	tpl := Template{ID: "CVE-2024-12345"}
	got := extractCves(tpl, "http/cves/2024/CVE-2024-12345.yaml")
	if len(got) != 1 || got[0] != "CVE-2024-12345" {
		t.Fatalf("got %v", got)
	}
}

func TestExtractCves_DedupAcrossSources(t *testing.T) {
	// Real CVE IDs use at least 4 digits after the year — the regex
	// requires that, so the test fixtures must too.
	tpl := Template{
		ID:   "CVE-2023-1234",
		Info: TemplateInfo{Tags: mkNode(t, `"cve,2023,CVE-2023-1234"`)},
	}
	got := extractCves(tpl, "http/cves/2023/CVE-2023-1234.yaml")
	sort.Strings(got)
	want := []string{"CVE-2023-1234"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExtractCwes(t *testing.T) {
	tpl := Template{Info: TemplateInfo{Classification: Classification{
		CweID: mkNode(t, "[\"cwe-79\",\"CWE-89\"]"),
	}}}
	got := extractCwes(tpl)
	sort.Strings(got)
	want := []string{"CWE-79", "CWE-89"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseTemplate(t *testing.T) {
	yamlBytes := []byte(`
id: CVE-2024-99999
info:
  name: Example CVE template
  author:
    - alice
    - bob
  severity: high
  description: |
    Demo template.
  tags: cve,2024,wordpress
  classification:
    cve-id: CVE-2024-99999
    cwe-id:
      - cwe-79
`)
	tpl, err := parseTemplate(yamlBytes)
	if err != nil {
		t.Fatal(err)
	}
	if tpl.ID != "CVE-2024-99999" {
		t.Fatalf("id %q", tpl.ID)
	}
	if tpl.Info.Severity != "high" {
		t.Fatalf("severity %q", tpl.Info.Severity)
	}
	authors := flattenStringNode(tpl.Info.Author)
	if !reflect.DeepEqual(authors, []string{"alice", "bob"}) {
		t.Fatalf("authors %v", authors)
	}
}
