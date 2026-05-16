package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds the global application configuration.
type Config struct {
	DatabaseURL    string `mapstructure:"database_url"`
	IngestInterval string `mapstructure:"ingest_interval"`
	ServerBind     string `mapstructure:"server_bind"`
	Feeds          []Feed `mapstructure:"feeds"`

	NVD      NvdConfig      `mapstructure:"nvd"`
	EPSS     EpssConfig     `mapstructure:"epss"`
	KEV      KevConfig      `mapstructure:"kev"`
	OSV      OsvConfig      `mapstructure:"osv"`
	GHSA     GhsaConfig     `mapstructure:"ghsa"`
	Abusech  AbusechConfig  `mapstructure:"abusech"`
	MSF      MsfConfig      `mapstructure:"msf"`
	Nuclei   NucleiConfig   `mapstructure:"nuclei"`
	Alerting AlertingConfig `mapstructure:"alerting"`
}

// Feed represents a single RSS/Atom source configuration.
type Feed struct {
	Name     string   `mapstructure:"name"`
	URL      string   `mapstructure:"url"`
	FeedType string   `mapstructure:"feed_type"`
	Tags     []string `mapstructure:"tags"`
}

type NvdConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	PollInterval string `mapstructure:"poll_interval"`
	PageSize     int    `mapstructure:"page_size"`
	ApiKey       string `mapstructure:"api_key"`
	URL          string `mapstructure:"url"`
}

type EpssConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	PollInterval string `mapstructure:"poll_interval"`
	URL          string `mapstructure:"url"`
	PageSize     int    `mapstructure:"page_size"`
}

type KevConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	PollInterval string `mapstructure:"poll_interval"`
	URL          string `mapstructure:"url"`
}

// OsvConfig controls the OSV (Open Source Vulnerabilities) ingestor.
// URL defaults to the GCS public bucket; Ecosystems is the list of
// per-ecosystem bundles to poll (PyPI, npm, Go, Maven, RubyGems, crates.io,
// Packagist, NuGet, Pub, Hex, Hackage, …).
type OsvConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	PollInterval string   `mapstructure:"poll_interval"`
	URL          string   `mapstructure:"url"`
	Ecosystems   []string `mapstructure:"ecosystems"`
}

// GhsaConfig controls the GitHub Security Advisory Database ingestor.
// URL defaults to api.github.com/advisories. Token is an optional GitHub
// PAT — anonymous works but rate-limits at 60 req/h vs 5000 req/h
// authenticated (a 100× difference matters for the initial backfill).
type GhsaConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	PollInterval string `mapstructure:"poll_interval"`
	URL          string `mapstructure:"url"`
	Token        string `mapstructure:"token"`
	PageSize     int    `mapstructure:"page_size"` // capped at 100 by GitHub API
}

// AbusechConfig controls the abuse.ch ingestors. abuse.ch unified all of
// their feeds onto a single Auth-Key in 2024; APIKey is shared across the
// three sub-runners. URLhaus' public CSV still works without auth so it
// keeps running even when APIKey is empty.
type AbusechConfig struct {
	APIKey        string              `mapstructure:"api_key"`
	URLhaus       UrlhausConfig       `mapstructure:"urlhaus"`
	ThreatFox     ThreatFoxConfig     `mapstructure:"threatfox"`
	MalwareBazaar MalwareBazaarConfig `mapstructure:"malwarebazaar"`
}

// UrlhausConfig controls the URLhaus CSV ingestor. URL defaults to the
// public `csv_recent` endpoint which covers the last few days of URLs.
type UrlhausConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	PollInterval string `mapstructure:"poll_interval"`
	URL          string `mapstructure:"url"`
}

// ThreatFoxConfig controls the ThreatFox JSON-API ingestor.
// URL defaults to https://threatfox-api.abuse.ch/api/v1/. Days is the
// lookback window per poll (1-7); the abuse.ch upstream caps it at 7.
type ThreatFoxConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	PollInterval string `mapstructure:"poll_interval"`
	URL          string `mapstructure:"url"`
	Days         int    `mapstructure:"days"`
}

// MalwareBazaarConfig controls the MalwareBazaar form-API ingestor.
// URL defaults to https://mb-api.abuse.ch/api/v1/. Selector accepts
// "time" (last 60 minutes — auth required) or a count like "100" / "1000".
type MalwareBazaarConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	PollInterval string `mapstructure:"poll_interval"`
	URL          string `mapstructure:"url"`
	Selector     string `mapstructure:"selector"`
}

// MsfConfig controls the Metasploit Framework module metadata ingestor.
// URL defaults to the raw db/modules_metadata_base.json in the master
// branch of github.com/rapid7/metasploit-framework.
type MsfConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	PollInterval string `mapstructure:"poll_interval"`
	URL          string `mapstructure:"url"`
}

// NucleiConfig controls the Nuclei templates ingestor. URL defaults to the
// main-branch tarball at github.com/projectdiscovery/nuclei-templates.
// Subdirs restricts which directories to walk (default = all common
// template paths).
type NucleiConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	PollInterval string   `mapstructure:"poll_interval"`
	URL          string   `mapstructure:"url"`
	Subdirs      []string `mapstructure:"subdirs"`
}

type AlertingConfig struct {
	Enabled      bool            `mapstructure:"enabled"`
	PollInterval string          `mapstructure:"poll_interval"`
	Webhooks     []WebhookConfig `mapstructure:"webhooks"`
	LookbackDays int             `mapstructure:"lookback_days"`
}

type WebhookConfig struct {
	Name string `mapstructure:"name"`
	URL  string `mapstructure:"url"`
	Type string `mapstructure:"type"` // "slack" or "generic"
}

// Load reads configuration from config files and environment variables.
func Load() (*Config, error) {
	v := viper.New()

	// Default values
	v.SetDefault("server_bind", "0.0.0.0:9101")
	v.SetDefault("ingest_interval", "1h")

	// Config file setup
	v.SetConfigName("Config") // name of config file (without extension)
	v.SetConfigType("toml")   // REQUIRED if the config file does not have the extension in the name
	v.AddConfigPath(".")      // optionally look for config in the working directory
	v.AddConfigPath("/etc/tigerfetch/")
	v.AddConfigPath("$HOME/.tigerfetch")

	// Environment variable override
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// AutomaticEnv only resolves env vars during Get() — not during Unmarshal
	// of nested struct keys that aren't already known via the config file or
	// a SetDefault. Bind the credential keys explicitly so an empty/missing
	// TOML stanza doesn't shadow the env var.
	_ = v.BindEnv("abusech.api_key", "ABUSECH_API_KEY")
	_ = v.BindEnv("ghsa.token", "GHSA_TOKEN")
	_ = v.BindEnv("nvd.api_key", "NVD_API_KEY")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// It's okay if config file is not found, we rely on defaults/env
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// GetIngestDuration parses the IngestInterval string into a time.Duration.
func (c *Config) GetIngestDuration() (time.Duration, error) {
	return time.ParseDuration(c.IngestInterval)
}

func (c *NvdConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *EpssConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *KevConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *OsvConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *GhsaConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *UrlhausConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *ThreatFoxConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *MalwareBazaarConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *MsfConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *NucleiConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *AlertingConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}
