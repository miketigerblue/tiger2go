package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/miketigerblue/tiger2go/internal/logger"
	"github.com/miketigerblue/tiger2go/pkg/cisa"
	"github.com/miketigerblue/tiger2go/pkg/config"
	"github.com/miketigerblue/tiger2go/pkg/epss"
	"github.com/miketigerblue/tiger2go/pkg/feeds"
	"github.com/miketigerblue/tiger2go/pkg/models"
	"github.com/miketigerblue/tiger2go/pkg/nvd"
	"github.com/miketigerblue/tiger2go/pkg/storage"
)

const (
	version = "1.0.0"
)

func main() {
	// Command line flags
	configPath := flag.String("config", "config.json", "Path to configuration file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	initConfig := flag.Bool("init", false, "Initialize default configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	fetchOnly := flag.Bool("fetch-only", false, "Only fetch advisories without enrichment")
	enrichOnly := flag.Bool("enrich-only", false, "Only enrich existing advisories")
	outputJSON := flag.Bool("json", false, "Output results as JSON")
	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Printf("tigerfetch version %s\n", version)
		os.Exit(0)
	}

	// Initialize logger
	log := logger.New(*debug)

	// Initialize config
	if *initConfig {
		cfg := config.DefaultConfig()
		if err := config.SaveConfig(cfg, *configPath); err != nil {
			log.Fatal("Failed to save default config: %v", err)
		}
		log.Info("Default configuration saved to %s", *configPath)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal("Failed to load config: %v", err)
	}

	// Initialize storage
	store, err := storage.NewStore(cfg.Storage.DataDir)
	if err != nil {
		log.Fatal("Failed to initialize storage: %v", err)
	}

	ctx := context.Background()

	if *enrichOnly {
		// Load existing advisories and enrich them
		advisories, err := store.LoadAdvisories(time.Now())
		if err != nil {
			log.Fatal("Failed to load advisories: %v", err)
		}
		enrichedAdvisories := enrichAdvisories(ctx, cfg, log, advisories)
		if err := store.SaveEnrichedAdvisories(enrichedAdvisories); err != nil {
			log.Fatal("Failed to save enriched advisories: %v", err)
		}
		log.Info("Enriched %d advisories", len(enrichedAdvisories))
		os.Exit(0)
	}

	// Fetch advisories from feeds
	log.Info("Starting tigerfetch v%s", version)
	log.Info("Fetching security advisories from configured feeds...")

	feedParser := feeds.NewFeedParser(cfg.GetHTTPTimeout())
	var allAdvisories []models.Advisory

	for _, feedCfg := range cfg.Feeds {
		if !feedCfg.Enabled {
			log.Debug("Skipping disabled feed: %s", feedCfg.Name)
			continue
		}

		log.Info("Fetching from %s: %s", feedCfg.Name, feedCfg.URL)
		advisories, err := feedParser.FetchFeed(ctx, feedCfg.URL, feedCfg.Name)
		if err != nil {
			log.Error("Failed to fetch feed %s: %v", feedCfg.Name, err)
			continue
		}

		log.Info("Found %d advisories from %s", len(advisories), feedCfg.Name)
		allAdvisories = append(allAdvisories, advisories...)
	}

	if len(allAdvisories) == 0 {
		log.Info("No advisories found")
		os.Exit(0)
	}

	// Save raw advisories
	if err := store.SaveAdvisories(allAdvisories); err != nil {
		log.Error("Failed to save advisories: %v", err)
	}

	log.Info("Total advisories fetched: %d", len(allAdvisories))

	if *fetchOnly {
		if *outputJSON {
			outputJSONResults(allAdvisories)
		}
		os.Exit(0)
	}

	// Enrich advisories
	enrichedAdvisories := enrichAdvisories(ctx, cfg, log, allAdvisories)

	// Save enriched advisories
	if err := store.SaveEnrichedAdvisories(enrichedAdvisories); err != nil {
		log.Error("Failed to save enriched advisories: %v", err)
	}

	log.Info("Successfully enriched %d advisories", len(enrichedAdvisories))

	// Output results
	if *outputJSON {
		outputJSONResults(enrichedAdvisories)
	} else {
		printSummary(log, enrichedAdvisories)
	}
}

func enrichAdvisories(ctx context.Context, cfg *config.Config, log *logger.Logger, advisories []models.Advisory) []models.EnrichedAdvisory {
	log.Info("Enriching advisories with CVE data...")

	// Initialize clients
	nvdClient := nvd.NewClient(cfg.NVD.APIKey, cfg.GetHTTPTimeout())
	cisaClient := cisa.NewClient(cfg.GetHTTPTimeout())
	epssClient := epss.NewClient(cfg.GetHTTPTimeout())

	// Collect all unique CVE IDs
	cveIDSet := make(map[string]bool)
	for _, advisory := range advisories {
		for _, cveID := range advisory.CVEIDs {
			cveIDSet[cveID] = true
		}
	}

	var allCVEIDs []string
	for cveID := range cveIDSet {
		allCVEIDs = append(allCVEIDs, cveID)
	}

	log.Info("Found %d unique CVE IDs to enrich", len(allCVEIDs))

	// Fetch CVE data from NVD (with rate limiting)
	var allCVEs []models.CVE
	if len(allCVEIDs) > 0 {
		log.Info("Fetching CVE data from NVD (this may take a while due to rate limiting)...")
		cves, err := nvdClient.GetCVEs(ctx, allCVEIDs)
		if err != nil {
			log.Error("Failed to fetch CVEs from NVD: %v", err)
		} else {
			allCVEs = cves
			log.Info("Fetched %d CVEs from NVD", len(allCVEs))
		}
	}

	// Fetch KEV data from CISA
	var kevMap map[string]models.KEV
	if len(allCVEIDs) > 0 {
		log.Info("Fetching KEV data from CISA...")
		kevs, err := cisaClient.GetKEVByCVE(ctx, allCVEIDs)
		if err != nil {
			log.Error("Failed to fetch KEVs: %v", err)
		} else {
			kevMap = kevs
			log.Info("Found %d KEVs", len(kevMap))
		}
	}

	// Fetch EPSS scores
	var epssMap map[string]models.EPSSScore
	if len(allCVEIDs) > 0 {
		log.Info("Fetching EPSS scores...")
		scores, err := epssClient.GetEPSSScores(ctx, allCVEIDs)
		if err != nil {
			log.Error("Failed to fetch EPSS scores: %v", err)
		} else {
			epssMap = scores
			log.Info("Fetched %d EPSS scores", len(epssMap))
		}
	}

	// Create CVE lookup map
	cveMap := make(map[string]models.CVE)
	for _, cve := range allCVEs {
		cveMap[cve.ID] = cve
	}

	// Enrich advisories
	enriched := make([]models.EnrichedAdvisory, 0, len(advisories))
	for _, advisory := range advisories {
		enrichedAdv := models.EnrichedAdvisory{
			Advisory:   advisory,
			CVEs:       []models.CVE{},
			KEVs:       []models.KEV{},
			EPSSScores: make(map[string]models.EPSSScore),
		}

		for _, cveID := range advisory.CVEIDs {
			if cve, found := cveMap[cveID]; found {
				enrichedAdv.CVEs = append(enrichedAdv.CVEs, cve)
			}
			if kev, found := kevMap[cveID]; found {
				enrichedAdv.KEVs = append(enrichedAdv.KEVs, kev)
			}
			if score, found := epssMap[cveID]; found {
				enrichedAdv.EPSSScores[cveID] = score
			}
		}

		enriched = append(enriched, enrichedAdv)
	}

	return enriched
}

func printSummary(log *logger.Logger, enrichedAdvisories []models.EnrichedAdvisory) {
	log.Info("\n=== Summary ===")
	log.Info("Total advisories: %d", len(enrichedAdvisories))

	totalCVEs := 0
	totalKEVs := 0
	totalEPSS := 0

	for _, adv := range enrichedAdvisories {
		totalCVEs += len(adv.CVEs)
		totalKEVs += len(adv.KEVs)
		totalEPSS += len(adv.EPSSScores)
	}

	log.Info("Total CVEs enriched: %d", totalCVEs)
	log.Info("Total KEVs found: %d", totalKEVs)
	log.Info("Total EPSS scores: %d", totalEPSS)

	// Show advisories with KEVs (critical)
	if totalKEVs > 0 {
		log.Info("\n=== Advisories with Known Exploited Vulnerabilities ===")
		for _, adv := range enrichedAdvisories {
			if len(adv.KEVs) > 0 {
				log.Info("- %s (%s)", adv.Advisory.Title, adv.Advisory.Source)
				for _, kev := range adv.KEVs {
					log.Info("  * %s: %s", kev.CVEID, kev.VulnerabilityName)
				}
			}
		}
	}
}

func outputJSONResults(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}
