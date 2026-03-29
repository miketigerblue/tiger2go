package metrics

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ---------------------------------------------------------------------------
// Feed ingestion
// ---------------------------------------------------------------------------

var FeedFetches = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_feed_fetches_total",
	Help: "Total feed fetch attempts by feed and outcome.",
}, []string{"feed_name", "status"})

var FeedItemsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_feed_items_processed_total",
	Help: "Items successfully saved per feed.",
}, []string{"feed_name"})

var FeedItemsFailed = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_feed_items_failed_total",
	Help: "Items that failed processing per feed.",
}, []string{"feed_name"})

var FeedItemsNew = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_feed_items_new_total",
	Help: "Items that were genuinely new (archive INSERT succeeded).",
}, []string{"feed_name"})

var FeedItemsUpdated = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_feed_items_updated_total",
	Help: "Items that hit the ON CONFLICT UPDATE path in current.",
}, []string{"feed_name"})

var FeedItemsEmptyContent = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_feed_items_empty_content_total",
	Help: "Items where both content and summary are empty after sanitization.",
}, []string{"feed_name"})

var FeedFetchDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "tigerfetch_feed_fetch_duration_seconds",
	Help:    "Duration of each FetchAndSave call.",
	Buckets: []float64{0.5, 1, 2, 5, 10, 30},
}, []string{"feed_name"})

var FeedLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "tigerfetch_feed_last_success_timestamp",
	Help: "Unix timestamp of last successful fetch per feed.",
}, []string{"feed_name"})

// ---------------------------------------------------------------------------
// NVD
// ---------------------------------------------------------------------------

var NvdFetches = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_nvd_fetches_total",
	Help: "NVD HTTP fetch attempts by outcome.",
}, []string{"status"})

var NvdCvesProcessed = promauto.NewCounter(prometheus.CounterOpts{
	Name: "tigerfetch_nvd_cves_processed_total",
	Help: "Total CVEs upserted from NVD.",
})

var NvdCvesWithoutCvss = promauto.NewCounter(prometheus.CounterOpts{
	Name: "tigerfetch_nvd_cves_without_cvss_total",
	Help: "CVEs ingested with no CVSS score.",
})

var NvdBatchSize = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "tigerfetch_nvd_batch_size",
	Help:    "Distribution of NVD batch sizes.",
	Buckets: []float64{10, 50, 100, 500, 1000, 2000},
})

var NvdRateLimits = promauto.NewCounter(prometheus.CounterOpts{
	Name: "tigerfetch_nvd_rate_limits_total",
	Help: "Times NVD returned 429 or 503.",
})

var NvdApiErrors = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_nvd_api_errors_total",
	Help: "Unexpected NVD HTTP status codes.",
}, []string{"status_code"})

var NvdRunDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "tigerfetch_nvd_run_duration_seconds",
	Help:    "Duration of a full NVD Run() cycle.",
	Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600},
})

var NvdCursorLag = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "tigerfetch_nvd_cursor_lag_seconds",
	Help: "Seconds between NVD cursor and now.",
})

// ---------------------------------------------------------------------------
// EPSS
// ---------------------------------------------------------------------------

var EpssRuns = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_epss_runs_total",
	Help: "EPSS Run() outcomes (success, error, skipped).",
}, []string{"status"})

var EpssRecordsProcessed = promauto.NewCounter(prometheus.CounterOpts{
	Name: "tigerfetch_epss_records_processed_total",
	Help: "Total EPSS rows inserted.",
})

var EpssPagesFetched = promauto.NewCounter(prometheus.CounterOpts{
	Name: "tigerfetch_epss_pages_fetched_total",
	Help: "EPSS API pages fetched.",
})

var EpssRunDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "tigerfetch_epss_run_duration_seconds",
	Help:    "Duration of a full EPSS Run() cycle.",
	Buckets: []float64{1, 5, 15, 30, 60, 120, 300},
})

var EpssCursorLag = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "tigerfetch_epss_cursor_lag_seconds",
	Help: "Seconds between latest EPSS date and now.",
})

// ---------------------------------------------------------------------------
// KEV
// ---------------------------------------------------------------------------

var KevFetches = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_kev_fetches_total",
	Help: "KEV Run() outcomes (success, error, up_to_date).",
}, []string{"status"})

var KevVulnsProcessed = promauto.NewCounter(prometheus.CounterOpts{
	Name: "tigerfetch_kev_vulns_processed_total",
	Help: "Total KEV vulnerabilities upserted.",
})

var KevRunDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "tigerfetch_kev_run_duration_seconds",
	Help:    "Duration of a full KEV Run() cycle.",
	Buckets: []float64{1, 5, 10, 30, 60},
})

var KevCursorLag = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "tigerfetch_kev_cursor_lag_seconds",
	Help: "Seconds between KEV cursor and now.",
})

// ---------------------------------------------------------------------------
// Upstream HTTP latency (all sources)
// ---------------------------------------------------------------------------

var UpstreamRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "tigerfetch_upstream_request_duration_seconds",
	Help:    "Upstream HTTP response time by source.",
	Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
}, []string{"source"})

// ---------------------------------------------------------------------------
// App info
// ---------------------------------------------------------------------------

var buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "tigerfetch_build_info",
	Help: "Build metadata (constant 1).",
}, []string{"version", "go_version", "commit"})

var startTime = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "tigerfetch_start_time_seconds",
	Help: "Unix timestamp when the process started.",
})

// RecordBuildInfo sets the build_info gauge to 1 with the given labels.
func RecordBuildInfo(version, commit string) {
	buildInfo.WithLabelValues(version, runtime.Version(), commit).Set(1)
}

// RecordStartTime records the current time as process start.
func RecordStartTime() {
	startTime.Set(float64(time.Now().Unix()))
}
