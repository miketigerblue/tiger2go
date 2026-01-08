package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds the application configuration
type Config struct {
	Feeds    []FeedConfig  `json:"feeds"`
	NVD      NVDConfig     `json:"nvd"`
	Storage  StorageConfig `json:"storage"`
	HTTP     HTTPConfig    `json:"http"`
}

// FeedConfig holds feed-specific configuration
type FeedConfig struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Enabled bool  `json:"enabled"`
}

// NVDConfig holds NVD API configuration
type NVDConfig struct {
	APIKey      string `json:"api_key"`
	RateLimitMS int    `json:"rate_limit_ms"` // Milliseconds between requests
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	DataDir string `json:"data_dir"`
}

// HTTPConfig holds HTTP client configuration
type HTTPConfig struct {
	TimeoutSeconds int `json:"timeout_seconds"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Feeds: []FeedConfig{
			{
				Name:    "NVD",
				URL:     "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
				Enabled: true,
			},
			{
				Name:    "CISA",
				URL:     "https://www.cisa.gov/cybersecurity-advisories/all.xml",
				Enabled: true,
			},
		},
		NVD: NVDConfig{
			APIKey:      "",
			RateLimitMS: 6000,
		},
		Storage: StorageConfig{
			DataDir: "./data",
		},
		HTTP: HTTPConfig{
			TimeoutSeconds: 30,
		},
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return &cfg, nil
}

// SaveConfig saves configuration to a file
func SaveConfig(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	return nil
}

// GetHTTPTimeout returns the HTTP client timeout duration
func (c *Config) GetHTTPTimeout() time.Duration {
	return time.Duration(c.HTTP.TimeoutSeconds) * time.Second
}

// GetNVDRateLimit returns the NVD API rate limit duration
func (c *Config) GetNVDRateLimit() time.Duration {
	return time.Duration(c.NVD.RateLimitMS) * time.Millisecond
}
