package storage

import (
	"os"
	"testing"
	"time"

	"github.com/miketigerblue/tiger2go/pkg/models"
)

func TestNewStore(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewStore(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	if store.dataDir != tmpDir {
		t.Errorf("Expected dataDir %s, got %s", tmpDir, store.dataDir)
	}

	// Verify directory was created
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Error("Expected data directory to be created")
	}
}

func TestSaveAndLoadAdvisories(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewStore(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	advisories := []models.Advisory{
		{
			ID:          "ADV-001",
			Title:       "Test Advisory",
			Description: "Test description",
			Link:        "https://example.com/advisory",
			Published:   time.Now(),
			Source:      "TestSource",
			CVEIDs:      []string{"CVE-2024-1234"},
		},
	}

	// Save advisories
	if err := store.SaveAdvisories(advisories); err != nil {
		t.Fatalf("Failed to save advisories: %v", err)
	}

	// Load advisories
	loaded, err := store.LoadAdvisories(time.Now())
	if err != nil {
		t.Fatalf("Failed to load advisories: %v", err)
	}

	if len(loaded) != 1 {
		t.Fatalf("Expected 1 advisory, got %d", len(loaded))
	}

	if loaded[0].ID != "ADV-001" {
		t.Errorf("Expected ID ADV-001, got %s", loaded[0].ID)
	}
}

func TestSaveEnrichedAdvisories(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewStore(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	enriched := []models.EnrichedAdvisory{
		{
			Advisory: models.Advisory{
				ID:     "ADV-001",
				Title:  "Test Advisory",
				Source: "TestSource",
			},
			CVEs: []models.CVE{
				{
					ID:          "CVE-2024-1234",
					Description: "Test vulnerability",
				},
			},
		},
	}

	if err := store.SaveEnrichedAdvisories(enriched); err != nil {
		t.Fatalf("Failed to save enriched advisories: %v", err)
	}
}

func TestSaveCVEs(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewStore(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	cves := []models.CVE{
		{
			ID:          "CVE-2024-1234",
			Description: "Test vulnerability",
			Published:   time.Now(),
		},
	}

	if err := store.SaveCVEs(cves); err != nil {
		t.Fatalf("Failed to save CVEs: %v", err)
	}
}

func TestSaveKEVs(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewStore(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	kevs := []models.KEV{
		{
			CVEID:             "CVE-2024-1234",
			VulnerabilityName: "Test Vulnerability",
		},
	}

	if err := store.SaveKEVs(kevs); err != nil {
		t.Fatalf("Failed to save KEVs: %v", err)
	}
}

func TestSaveEPSSScores(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewStore(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	scores := map[string]models.EPSSScore{
		"CVE-2024-1234": {
			CVEID: "CVE-2024-1234",
			EPSS:  0.75,
		},
	}

	if err := store.SaveEPSSScores(scores); err != nil {
		t.Fatalf("Failed to save EPSS scores: %v", err)
	}
}
