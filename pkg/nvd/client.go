package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/miketigerblue/tiger2go/pkg/models"
)

const (
	nvdAPIBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

// Client handles interactions with the NVD API
type Client struct {
	apiKey      string
	httpClient  *http.Client
	baseURL     string
	rateLimit   time.Duration
}

// NewClient creates a new NVD API client
func NewClient(apiKey string, timeout time.Duration, rateLimit time.Duration) *Client {
	return &Client{
		apiKey:      apiKey,
		httpClient:  &http.Client{Timeout: timeout},
		baseURL:     nvdAPIBaseURL,
		rateLimit:   rateLimit,
	}
}

// NVD API response structures
type nvdResponse struct {
	ResultsPerPage  int              `json:"resultsPerPage"`
	StartIndex      int              `json:"startIndex"`
	TotalResults    int              `json:"totalResults"`
	Format          string           `json:"format"`
	Version         string           `json:"version"`
	Timestamp       string           `json:"timestamp"`
	Vulnerabilities []vulnerability  `json:"vulnerabilities"`
}

type vulnerability struct {
	CVE cveItem `json:"cve"`
}

type cveItem struct {
	ID          string       `json:"id"`
	SourceID    string       `json:"sourceIdentifier"`
	Published   string       `json:"published"`
	Modified    string       `json:"lastModified"`
	VulnStatus  string       `json:"vulnStatus"`
	Descriptions []description `json:"descriptions"`
	Metrics     metrics      `json:"metrics,omitempty"`
	References  []reference  `json:"references,omitempty"`
}

type description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	CVSSMetricV31 []cvssMetric `json:"cvssMetricV31,omitempty"`
	CVSSMetricV30 []cvssMetric `json:"cvssMetricV30,omitempty"`
	CVSSMetricV2  []cvssMetric `json:"cvssMetricV2,omitempty"`
}

type cvssMetric struct {
	Source              string   `json:"source"`
	Type                string   `json:"type"`
	CVSSData            cvssData `json:"cvssData"`
	ExploitabilityScore float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64  `json:"impactScore,omitempty"`
}

type cvssData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity,omitempty"`
}

type reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"`
}

// GetCVE fetches CVE information from NVD
func (c *Client) GetCVE(ctx context.Context, cveID string) (*models.CVE, error) {
	params := url.Values{}
	params.Add("cveId", cveID)

	reqURL := fmt.Sprintf("%s?%s", c.baseURL, params.Encode())
	
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
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

	var nvdResp nvdResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}

	return convertNVDToCVE(nvdResp.Vulnerabilities[0].CVE), nil
}

// GetCVEs fetches multiple CVEs from NVD
func (c *Client) GetCVEs(ctx context.Context, cveIDs []string) ([]models.CVE, error) {
	cves := make([]models.CVE, 0, len(cveIDs))
	
	for _, cveID := range cveIDs {
		cve, err := c.GetCVE(ctx, cveID)
		if err != nil {
			// Log error but continue with other CVEs
			continue
		}
		cves = append(cves, *cve)
		
		// Rate limiting: wait between requests
		if c.rateLimit > 0 {
			time.Sleep(c.rateLimit)
		}
	}
	
	return cves, nil
}

func convertNVDToCVE(nvdCVE cveItem) *models.CVE {
	cve := &models.CVE{
		ID: nvdCVE.ID,
	}

	// Get English description
	for _, desc := range nvdCVE.Descriptions {
		if desc.Lang == "en" {
			cve.Description = desc.Value
			break
		}
	}

	// Parse timestamps
	if published, err := time.Parse("2006-01-02T15:04:05.000", nvdCVE.Published); err == nil {
		cve.Published = published
	}
	if modified, err := time.Parse("2006-01-02T15:04:05.000", nvdCVE.Modified); err == nil {
		cve.Modified = modified
	}

	// Extract CVSS information (prefer v3.1, then v3.0, then v2)
	if len(nvdCVE.Metrics.CVSSMetricV31) > 0 {
		metric := nvdCVE.Metrics.CVSSMetricV31[0]
		cve.CVSS = models.CVSS{
			Version:  metric.CVSSData.Version,
			Score:    metric.CVSSData.BaseScore,
			Vector:   metric.CVSSData.VectorString,
			Severity: metric.CVSSData.BaseSeverity,
		}
	} else if len(nvdCVE.Metrics.CVSSMetricV30) > 0 {
		metric := nvdCVE.Metrics.CVSSMetricV30[0]
		cve.CVSS = models.CVSS{
			Version:  metric.CVSSData.Version,
			Score:    metric.CVSSData.BaseScore,
			Vector:   metric.CVSSData.VectorString,
			Severity: metric.CVSSData.BaseSeverity,
		}
	} else if len(nvdCVE.Metrics.CVSSMetricV2) > 0 {
		metric := nvdCVE.Metrics.CVSSMetricV2[0]
		cve.CVSS = models.CVSS{
			Version: metric.CVSSData.Version,
			Score:   metric.CVSSData.BaseScore,
			Vector:  metric.CVSSData.VectorString,
		}
	}

	// Extract references
	for _, ref := range nvdCVE.References {
		cve.References = append(cve.References, ref.URL)
	}

	return cve
}
