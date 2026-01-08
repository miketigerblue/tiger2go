package models

import (
	"testing"
	"time"
)

func TestCVEModel(t *testing.T) {
	cve := CVE{
		ID:          "CVE-2024-1234",
		Description: "Test vulnerability",
		Published:   time.Now(),
		Modified:    time.Now(),
		CVSS: CVSS{
			Version:  "3.1",
			Score:    9.8,
			Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Severity: "CRITICAL",
		},
	}

	if cve.ID != "CVE-2024-1234" {
		t.Errorf("Expected ID CVE-2024-1234, got %s", cve.ID)
	}
	if cve.CVSS.Score != 9.8 {
		t.Errorf("Expected score 9.8, got %f", cve.CVSS.Score)
	}
}

func TestAdvisoryModel(t *testing.T) {
	advisory := Advisory{
		ID:          "ADV-001",
		Title:       "Test Advisory",
		Description: "Test description with CVE-2024-1234",
		Link:        "https://example.com/advisory",
		Published:   time.Now(),
		Source:      "TestSource",
		CVEIDs:      []string{"CVE-2024-1234"},
		Enriched:    false,
	}

	if advisory.ID != "ADV-001" {
		t.Errorf("Expected ID ADV-001, got %s", advisory.ID)
	}
	if len(advisory.CVEIDs) != 1 {
		t.Errorf("Expected 1 CVE ID, got %d", len(advisory.CVEIDs))
	}
	if advisory.Enriched {
		t.Error("Expected enriched to be false")
	}
}

func TestKEVModel(t *testing.T) {
	kev := KEV{
		CVEID:             "CVE-2024-1234",
		VendorProject:     "Test Vendor",
		Product:           "Test Product",
		VulnerabilityName: "Test Vulnerability",
		DateAdded:         time.Now(),
		ShortDescription:  "Test description",
		RequiredAction:    "Apply patches",
		DueDate:           time.Now().AddDate(0, 0, 30),
	}

	if kev.CVEID != "CVE-2024-1234" {
		t.Errorf("Expected CVEID CVE-2024-1234, got %s", kev.CVEID)
	}
	if kev.RequiredAction != "Apply patches" {
		t.Errorf("Expected RequiredAction 'Apply patches', got %s", kev.RequiredAction)
	}
}

func TestEPSSScoreModel(t *testing.T) {
	score := EPSSScore{
		CVEID:      "CVE-2024-1234",
		EPSS:       0.75,
		Percentile: 0.95,
		Date:       time.Now(),
	}

	if score.CVEID != "CVE-2024-1234" {
		t.Errorf("Expected CVEID CVE-2024-1234, got %s", score.CVEID)
	}
	if score.EPSS != 0.75 {
		t.Errorf("Expected EPSS 0.75, got %f", score.EPSS)
	}
	if score.Percentile != 0.95 {
		t.Errorf("Expected Percentile 0.95, got %f", score.Percentile)
	}
}

func TestEnrichedAdvisoryModel(t *testing.T) {
	enriched := EnrichedAdvisory{
		Advisory: Advisory{
			ID:     "ADV-001",
			Title:  "Test Advisory",
			Source: "TestSource",
			CVEIDs: []string{"CVE-2024-1234"},
		},
		CVEs: []CVE{
			{
				ID:          "CVE-2024-1234",
				Description: "Test vulnerability",
			},
		},
		KEVs: []KEV{
			{
				CVEID:             "CVE-2024-1234",
				VulnerabilityName: "Test Vulnerability",
			},
		},
		EPSSScores: map[string]EPSSScore{
			"CVE-2024-1234": {
				CVEID: "CVE-2024-1234",
				EPSS:  0.75,
			},
		},
	}

	if len(enriched.CVEs) != 1 {
		t.Errorf("Expected 1 CVE, got %d", len(enriched.CVEs))
	}
	if len(enriched.KEVs) != 1 {
		t.Errorf("Expected 1 KEV, got %d", len(enriched.KEVs))
	}
	if len(enriched.EPSSScores) != 1 {
		t.Errorf("Expected 1 EPSS score, got %d", len(enriched.EPSSScores))
	}
}
