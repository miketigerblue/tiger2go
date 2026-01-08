package models

import "time"

// CVE represents a Common Vulnerabilities and Exposures entry
type CVE struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	CVSS        CVSS      `json:"cvss,omitempty"`
	References  []string  `json:"references,omitempty"`
	Affected    []string  `json:"affected,omitempty"`
}

// CVSS represents Common Vulnerability Scoring System data
type CVSS struct {
	Version string  `json:"version"`
	Score   float64 `json:"score"`
	Vector  string  `json:"vector"`
	Severity string `json:"severity"`
}

// Advisory represents a security advisory from an RSS/Atom feed
type Advisory struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Link        string    `json:"link"`
	Published   time.Time `json:"published"`
	Source      string    `json:"source"`
	CVEIDs      []string  `json:"cve_ids,omitempty"`
	Enriched    bool      `json:"enriched"`
}

// KEV represents a CISA Known Exploited Vulnerability
type KEV struct {
	CVEID             string    `json:"cve_id"`
	VendorProject     string    `json:"vendor_project"`
	Product           string    `json:"product"`
	VulnerabilityName string    `json:"vulnerability_name"`
	DateAdded         time.Time `json:"date_added"`
	ShortDescription  string    `json:"short_description"`
	RequiredAction    string    `json:"required_action"`
	DueDate           time.Time `json:"due_date"`
	Notes             string    `json:"notes,omitempty"`
}

// EPSSScore represents an Exploit Prediction Scoring System score
type EPSSScore struct {
	CVEID      string    `json:"cve_id"`
	EPSS       float64   `json:"epss"`
	Percentile float64   `json:"percentile"`
	Date       time.Time `json:"date"`
}

// EnrichedAdvisory combines an advisory with enriched CVE data
type EnrichedAdvisory struct {
	Advisory   Advisory             `json:"advisory"`
	CVEs       []CVE                `json:"cves,omitempty"`
	KEVs       []KEV                `json:"kevs,omitempty"`
	EPSSScores map[string]EPSSScore `json:"epss_scores,omitempty"`
}
