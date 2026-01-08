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

	NVD   NvdConfig   `mapstructure:"nvd"`
	MITRE MitreConfig `mapstructure:"mitre"`
	EPSS  EpssConfig  `mapstructure:"epss"`
	KEV   KevConfig   `mapstructure:"kev"`
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

type MitreConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	PollInterval string `mapstructure:"poll_interval"`
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

func (c *MitreConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *EpssConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

func (c *KevConfig) GetPollDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}
