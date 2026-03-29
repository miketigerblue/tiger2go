package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/cve"
	"tiger2go/internal/db"
	"tiger2go/internal/ingestor"
	"tiger2go/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	// Configure structured logging level from LOG_LEVEL env var
	var level slog.Level
	if err := level.UnmarshalText([]byte(os.Getenv("LOG_LEVEL"))); err != nil {
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	slog.Info("Starting TigerFetch...")

	// Record build info and start time
	metrics.RecordBuildInfo(version, commit)
	metrics.RecordStartTime()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// Validate database URL is set
	if cfg.DatabaseURL == "" {
		slog.Error("DATABASE_URL is required")
		os.Exit(1)
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Run database migrations
	slog.Info("Running database migrations...")
	if err := db.Migrate(cfg.DatabaseURL, "migrations"); err != nil {
		slog.Error("Failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Create database connection pool
	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to create database pool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Register pgxpool metrics collector
	metrics.RegisterDBCollector(pool)

	slog.Info("Database connected successfully")

	// Start HTTP server for metrics/health
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK")
	})
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:         cfg.ServerBind,
		Handler:      metrics.InstrumentHandler(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start server in goroutine
	go func() {
		slog.Info("Starting HTTP server", "addr", cfg.ServerBind)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Run CVE enrichment workers if enabled
	if cfg.NVD.Enabled {
		go func() {
			runner := cve.NewNvdRunner(pool, cfg.NVD)
			for {
				if err := runner.Run(ctx); err != nil {
					slog.Error("NVD runner error", "error", err)
				}
				interval, err := cfg.NVD.GetPollDuration()
				if err != nil {
					slog.Warn("Invalid NVD poll interval, using default 1h", "error", err)
					interval = 1 * time.Hour
				}
				if interval == 0 {
					interval = 1 * time.Hour
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(interval):
				}
			}
		}()
	}

	if cfg.KEV.Enabled {
		go func() {
			runner := cve.NewKevRunner(pool, cfg.KEV)
			for {
				if err := runner.Run(ctx); err != nil {
					slog.Error("KEV runner error", "error", err)
				}
				interval, err := cfg.KEV.GetPollDuration()
				if err != nil {
					slog.Warn("Invalid KEV poll interval, using default 1h", "error", err)
					interval = 1 * time.Hour
				}
				if interval == 0 {
					interval = 1 * time.Hour
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(interval):
				}
			}
		}()
	}

	if cfg.EPSS.Enabled {
		go func() {
			runner := cve.NewEpssRunner(pool, cfg.EPSS)
			for {
				if err := runner.Run(ctx); err != nil {
					slog.Error("EPSS runner error", "error", err)
				}
				interval, err := cfg.EPSS.GetPollDuration()
				if err != nil {
					slog.Warn("Invalid EPSS poll interval, using default 24h", "error", err)
					interval = 24 * time.Hour
				}
				if interval == 0 {
					interval = 24 * time.Hour
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(interval):
				}
			}
		}()
	}

	// Run RSS/Atom feed ingestor with bounded concurrency
	if len(cfg.Feeds) > 0 {
		go func() {
			client := ingestor.New(pool)
			interval, err := cfg.GetIngestDuration()
			if err != nil {
				slog.Warn("Invalid ingest_interval, using default 1h", "error", err)
				interval = 1 * time.Hour
			}
			const maxConcurrent = 5
			sem := make(chan struct{}, maxConcurrent)
			for {
				var wg sync.WaitGroup
				for _, feedCfg := range cfg.Feeds {
					wg.Add(1)
					sem <- struct{}{} // acquire slot
					go func(fc config.Feed) {
						defer wg.Done()
						defer func() { <-sem }() // release slot
						if err := client.FetchAndSave(ctx, fc); err != nil {
							slog.Error("Feed ingestion error", "feed", fc.Name, "error", err)
						}
					}(feedCfg)
				}
				wg.Wait()
				select {
				case <-ctx.Done():
					return
				case <-time.After(interval):
				}
			}
		}()
	}

	slog.Info("TigerFetch started successfully")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	slog.Info("Shutting down...")
	cancel() // Cancel context to signal goroutines to stop
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server shutdown error", "error", err)
	}

	slog.Info("Shutdown complete")
}
