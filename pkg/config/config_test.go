package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
	if len(cfg.Feeds) != 2 {
		t.Errorf("Expected 2 feeds, got %d", len(cfg.Feeds))
	}
	if cfg.Storage.DataDir != "./data" {
		t.Errorf("Expected data dir './data', got '%s'", cfg.Storage.DataDir)
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Create and save config
	cfg := DefaultConfig()
	cfg.NVD.APIKey = "test-key"
	cfg.Storage.DataDir = os.TempDir()

	if err := SaveConfig(cfg, tmpPath); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load config
	loadedCfg, err := LoadConfig(tmpPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if loadedCfg.NVD.APIKey != "test-key" {
		t.Errorf("Expected API key 'test-key', got '%s'", loadedCfg.NVD.APIKey)
	}
	if loadedCfg.Storage.DataDir != os.TempDir() {
		t.Errorf("Expected data dir '%s', got '%s'", os.TempDir(), loadedCfg.Storage.DataDir)
	}
}

func TestLoadConfigNonExistent(t *testing.T) {
	cfg, err := LoadConfig(os.TempDir() + "/non-existent-config.json")
	if err != nil {
		t.Fatalf("Expected no error for non-existent file, got: %v", err)
	}
	// Should return default config
	if cfg == nil {
		t.Fatal("Expected default config")
	}
}

func TestGetHTTPTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HTTP.TimeoutSeconds = 60
	
	timeout := cfg.GetHTTPTimeout()
	expected := 60 * time.Second
	if timeout != expected {
		t.Errorf("Expected timeout %v, got %v", expected, timeout)
	}
}

func TestGetNVDRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NVD.RateLimitMS = 5000
	
	rateLimit := cfg.GetNVDRateLimit()
	expected := 5000 * time.Millisecond
	if rateLimit != expected {
		t.Errorf("Expected rate limit %v, got %v", expected, rateLimit)
	}
}
