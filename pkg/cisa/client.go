package cisa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miketigerblue/tiger2go/pkg/models"
)

const (
	cisaKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// Client handles interactions with the CISA KEV catalog
type Client struct {
	httpClient *http.Client
	kevURL     string
}

// NewClient creates a new CISA KEV client
func NewClient(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		kevURL:     cisaKEVURL,
	}
}

// KEV Catalog response structure
type kevCatalog struct {
	Title           string           `json:"title"`
	CatalogVersion  string           `json:"catalogVersion"`
	DateReleased    string           `json:"dateReleased"`
	Count           int              `json:"count"`
	Vulnerabilities []kevVulnerability `json:"vulnerabilities"`
}

type kevVulnerability struct {
	CVEID                 string `json:"cveID"`
	VendorProject         string `json:"vendorProject"`
	Product               string `json:"product"`
	VulnerabilityName     string `json:"vulnerabilityName"`
	DateAdded             string `json:"dateAdded"`
	ShortDescription      string `json:"shortDescription"`
	RequiredAction        string `json:"requiredAction"`
	DueDate               string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                 string `json:"notes"`
}

// GetKEVCatalog fetches the entire CISA KEV catalog
func (c *Client) GetKEVCatalog(ctx context.Context) ([]models.KEV, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.kevURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var catalog kevCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	kevs := make([]models.KEV, 0, len(catalog.Vulnerabilities))
	for _, vuln := range catalog.Vulnerabilities {
		kev := convertToKEV(vuln)
		kevs = append(kevs, kev)
	}

	return kevs, nil
}

// GetKEVByCVE returns KEV information for specific CVE IDs
func (c *Client) GetKEVByCVE(ctx context.Context, cveIDs []string) (map[string]models.KEV, error) {
	allKEVs, err := c.GetKEVCatalog(ctx)
	if err != nil {
		return nil, err
	}

	// Create a map for quick lookup
	kevMap := make(map[string]models.KEV)
	for _, kev := range allKEVs {
		kevMap[kev.CVEID] = kev
	}

	// Filter by requested CVE IDs
	result := make(map[string]models.KEV)
	for _, cveID := range cveIDs {
		if kev, found := kevMap[cveID]; found {
			result[cveID] = kev
		}
	}

	return result, nil
}

func convertToKEV(vuln kevVulnerability) models.KEV {
	kev := models.KEV{
		CVEID:             vuln.CVEID,
		VendorProject:     vuln.VendorProject,
		Product:           vuln.Product,
		VulnerabilityName: vuln.VulnerabilityName,
		ShortDescription:  vuln.ShortDescription,
		RequiredAction:    vuln.RequiredAction,
		Notes:             vuln.Notes,
	}

	// Parse dates
	if dateAdded, err := time.Parse("2006-01-02", vuln.DateAdded); err == nil {
		kev.DateAdded = dateAdded
	}
	if dueDate, err := time.Parse("2006-01-02", vuln.DueDate); err == nil {
		kev.DueDate = dueDate
	}

	return kev
}
