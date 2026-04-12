package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetIngestDuration_Valid(t *testing.T) {
	cfg := &Config{IngestInterval: "30m"}
	d, err := cfg.GetIngestDuration()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Minute, d)
}

func TestGetIngestDuration_Empty(t *testing.T) {
	cfg := &Config{IngestInterval: ""}
	_, err := cfg.GetIngestDuration()
	assert.Error(t, err)
}

func TestGetIngestDuration_Invalid(t *testing.T) {
	cfg := &Config{IngestInterval: "not-a-duration"}
	_, err := cfg.GetIngestDuration()
	assert.Error(t, err)
}

func TestGetIngestDuration_Negative(t *testing.T) {
	cfg := &Config{IngestInterval: "-1h"}
	d, err := cfg.GetIngestDuration()
	require.NoError(t, err)
	assert.True(t, d < 0, "negative durations parse successfully but callers must validate")
}

func TestNvdGetPollDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantDur  time.Duration
		wantErr  bool
	}{
		{"valid 1h", "1h", time.Hour, false},
		{"valid 30s", "30s", 30 * time.Second, false},
		{"empty", "", 0, true},
		{"invalid", "xyz", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NvdConfig{PollInterval: tt.input}
			d, err := cfg.GetPollDuration()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantDur, d)
			}
		})
	}
}

func TestEpssGetPollDuration(t *testing.T) {
	cfg := &EpssConfig{PollInterval: "24h"}
	d, err := cfg.GetPollDuration()
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, d)
}

func TestKevGetPollDuration(t *testing.T) {
	cfg := &KevConfig{PollInterval: "6h"}
	d, err := cfg.GetPollDuration()
	require.NoError(t, err)
	assert.Equal(t, 6*time.Hour, d)
}

func TestLoad_Defaults(t *testing.T) {
	// Load without a config file — should succeed with defaults
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9101", cfg.ServerBind)
	assert.Equal(t, "1h", cfg.IngestInterval)
}
