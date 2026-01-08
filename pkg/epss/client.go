package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miketigerblue/tiger2go/pkg/models"
)

const (
	epssAPIURL = "https://api.first.org/data/v1/epss"
)

// Client handles interactions with the EPSS API
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new EPSS API client
func NewClient(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		baseURL:    epssAPIURL,
	}
}

// EPSS API response structures
type epssResponse struct {
	Status       string      `json:"status"`
	StatusCode   int         `json:"status-code"`
	Version      string      `json:"version"`
	Access       string      `json:"access"`
	Total        int         `json:"total"`
	Offset       int         `json:"offset"`
	Limit        int         `json:"limit"`
	Data         []epssData  `json:"data"`
}

type epssData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// GetEPSSScores fetches EPSS scores for multiple CVE IDs
func (c *Client) GetEPSSScores(ctx context.Context, cveIDs []string) (map[string]models.EPSSScore, error) {
	if len(cveIDs) == 0 {
		return map[string]models.EPSSScore{}, nil
	}

	// EPSS API accepts comma-separated CVE IDs
	params := url.Values{}
	params.Add("cve", strings.Join(cveIDs, ","))

	reqURL := fmt.Sprintf("%s?%s", c.baseURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
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

	var epssResp epssResponse
	if err := json.Unmarshal(body, &epssResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if epssResp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned error status: %s", epssResp.Status)
	}

	scores := make(map[string]models.EPSSScore)
	for _, data := range epssResp.Data {
		score, err := convertToEPSSScore(data)
		if err != nil {
			// Log error but continue with other scores
			continue
		}
		scores[data.CVE] = score
	}

	return scores, nil
}

// GetEPSSScore fetches EPSS score for a single CVE ID
func (c *Client) GetEPSSScore(ctx context.Context, cveID string) (*models.EPSSScore, error) {
	scores, err := c.GetEPSSScores(ctx, []string{cveID})
	if err != nil {
		return nil, err
	}

	score, found := scores[cveID]
	if !found {
		return nil, fmt.Errorf("EPSS score not found for %s", cveID)
	}

	return &score, nil
}

func convertToEPSSScore(data epssData) (models.EPSSScore, error) {
	score := models.EPSSScore{
		CVEID: data.CVE,
	}

	// Parse EPSS value
	epss, err := strconv.ParseFloat(data.EPSS, 64)
	if err != nil {
		return score, fmt.Errorf("parsing EPSS value: %w", err)
	}
	score.EPSS = epss

	// Parse percentile
	percentile, err := strconv.ParseFloat(data.Percentile, 64)
	if err != nil {
		return score, fmt.Errorf("parsing percentile value: %w", err)
	}
	score.Percentile = percentile

	// Parse date
	date, err := time.Parse("2006-01-02", data.Date)
	if err != nil {
		return score, fmt.Errorf("parsing date: %w", err)
	}
	score.Date = date

	return score, nil
}
