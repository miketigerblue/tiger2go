package ingestor

import (
	"testing"
	"time"
)

func TestProcessDeadline(t *testing.T) {
	cases := map[int]time.Duration{
		0:     30 * time.Second,
		20:    31 * time.Second,
		5049:  30*time.Second + 5049*50*time.Millisecond, // MSRC: ~4.7 minutes
		20000: 10 * time.Minute,                          // capped
	}
	for items, want := range cases {
		if got := processDeadline(items); got != want {
			t.Errorf("processDeadline(%d) = %v, want %v", items, got, want)
		}
	}
}
