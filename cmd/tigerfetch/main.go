package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tiger2go/internal/config"
	"tiger2go/internal/cve"
	"tiger2go/internal/db"
)

func main() {
	log.Println("Starting TigerFetch...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Validate database URL is set
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	ctx := context.Background()

	// Run database migrations
	log.Println("Running database migrations...")
	if err := db.Migrate(cfg.DatabaseURL, "migrations"); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Create database connection pool
	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to create database pool: %v", err)
	}
	defer pool.Close()

	log.Println("Database connected successfully")

	// Start HTTP server for metrics/health
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	server := &http.Server{
		Addr:         cfg.ServerBind,
		Handler:      http.DefaultServeMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting HTTP server on %s", cfg.ServerBind)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Run CVE enrichment workers if enabled
	if cfg.NVD.Enabled {
		go func() {
			runner := cve.NewNvdRunner(pool, cfg.NVD)
			for {
				if err := runner.Run(ctx); err != nil {
					log.Printf("NVD runner error: %v", err)
				}
				interval, _ := cfg.NVD.GetPollDuration()
				if interval == 0 {
					interval = 1 * time.Hour
				}
				time.Sleep(interval)
			}
		}()
	}

	if cfg.KEV.Enabled {
		go func() {
			runner := cve.NewKevRunner(pool, cfg.KEV)
			for {
				if err := runner.Run(ctx); err != nil {
					log.Printf("KEV runner error: %v", err)
				}
				interval, _ := cfg.KEV.GetPollDuration()
				if interval == 0 {
					interval = 1 * time.Hour
				}
				time.Sleep(interval)
			}
		}()
	}

	if cfg.EPSS.Enabled {
		go func() {
			runner := cve.NewEpssRunner(pool, cfg.EPSS)
			for {
				if err := runner.Run(ctx); err != nil {
					log.Printf("EPSS runner error: %v", err)
				}
				interval, _ := cfg.EPSS.GetPollDuration()
				if interval == 0 {
					interval = 24 * time.Hour
				}
				time.Sleep(interval)
			}
		}()
	}

	log.Println("TigerFetch started successfully")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
}
