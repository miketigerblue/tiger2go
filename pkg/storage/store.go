package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miketigerblue/tiger2go/pkg/models"
)

// Store handles data persistence
type Store struct {
	dataDir string
	mu      sync.RWMutex
}

// NewStore creates a new storage instance
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}

	return &Store{
		dataDir: dataDir,
	}, nil
}

// SaveAdvisories saves advisories to a JSON file
func (s *Store) SaveAdvisories(advisories []models.Advisory) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.dataDir, fmt.Sprintf("advisories_%s.json", time.Now().Format("2006-01-02")))
	
	data, err := json.MarshalIndent(advisories, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling advisories: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("writing advisories file: %w", err)
	}

	return nil
}

// SaveEnrichedAdvisories saves enriched advisories to a JSON file
func (s *Store) SaveEnrichedAdvisories(enrichedAdvisories []models.EnrichedAdvisory) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.dataDir, fmt.Sprintf("enriched_advisories_%s.json", time.Now().Format("2006-01-02")))
	
	data, err := json.MarshalIndent(enrichedAdvisories, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling enriched advisories: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("writing enriched advisories file: %w", err)
	}

	return nil
}

// SaveCVEs saves CVE data to a JSON file
func (s *Store) SaveCVEs(cves []models.CVE) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.dataDir, fmt.Sprintf("cves_%s.json", time.Now().Format("2006-01-02")))
	
	data, err := json.MarshalIndent(cves, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling CVEs: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("writing CVEs file: %w", err)
	}

	return nil
}

// SaveKEVs saves KEV data to a JSON file
func (s *Store) SaveKEVs(kevs []models.KEV) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.dataDir, fmt.Sprintf("kevs_%s.json", time.Now().Format("2006-01-02")))
	
	data, err := json.MarshalIndent(kevs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling KEVs: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("writing KEVs file: %w", err)
	}

	return nil
}

// SaveEPSSScores saves EPSS scores to a JSON file
func (s *Store) SaveEPSSScores(scores map[string]models.EPSSScore) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.dataDir, fmt.Sprintf("epss_scores_%s.json", time.Now().Format("2006-01-02")))
	
	data, err := json.MarshalIndent(scores, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling EPSS scores: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("writing EPSS scores file: %w", err)
	}

	return nil
}

// LoadAdvisories loads advisories from a JSON file
func (s *Store) LoadAdvisories(date time.Time) ([]models.Advisory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filename := filepath.Join(s.dataDir, fmt.Sprintf("advisories_%s.json", date.Format("2006-01-02")))
	
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading advisories file: %w", err)
	}

	var advisories []models.Advisory
	if err := json.Unmarshal(data, &advisories); err != nil {
		return nil, fmt.Errorf("unmarshaling advisories: %w", err)
	}

	return advisories, nil
}
