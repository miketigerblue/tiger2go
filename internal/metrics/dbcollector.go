package metrics

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// DBCollector implements prometheus.Collector using pgxpool.Stat().
// Fresh stats are read on every Prometheus scrape — no background goroutine needed.
type DBCollector struct {
	pool *pgxpool.Pool

	totalConns      *prometheus.Desc
	idleConns       *prometheus.Desc
	acquiredConns   *prometheus.Desc
	maxConns        *prometheus.Desc
	constructing    *prometheus.Desc
	acquireCount    *prometheus.Desc
	acquireDuration *prometheus.Desc
	emptyAcquire    *prometheus.Desc
}

// RegisterDBCollector creates and registers the pgxpool collector.
func RegisterDBCollector(pool *pgxpool.Pool) {
	prometheus.MustRegister(&DBCollector{
		pool: pool,
		totalConns: prometheus.NewDesc(
			"tigerfetch_db_pool_total_conns",
			"Total number of connections in the pool.",
			nil, nil,
		),
		idleConns: prometheus.NewDesc(
			"tigerfetch_db_pool_idle_conns",
			"Number of idle connections.",
			nil, nil,
		),
		acquiredConns: prometheus.NewDesc(
			"tigerfetch_db_pool_acquired_conns",
			"Number of currently acquired connections.",
			nil, nil,
		),
		maxConns: prometheus.NewDesc(
			"tigerfetch_db_pool_max_conns",
			"Maximum number of connections allowed.",
			nil, nil,
		),
		constructing: prometheus.NewDesc(
			"tigerfetch_db_pool_constructing_conns",
			"Connections currently being established.",
			nil, nil,
		),
		acquireCount: prometheus.NewDesc(
			"tigerfetch_db_pool_acquire_count_total",
			"Lifetime connection acquire count.",
			nil, nil,
		),
		acquireDuration: prometheus.NewDesc(
			"tigerfetch_db_pool_acquire_duration_seconds_total",
			"Cumulative time spent acquiring connections.",
			nil, nil,
		),
		emptyAcquire: prometheus.NewDesc(
			"tigerfetch_db_pool_empty_acquire_total",
			"Times pool was empty when acquire was requested.",
			nil, nil,
		),
	})
}

func (c *DBCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.totalConns
	ch <- c.idleConns
	ch <- c.acquiredConns
	ch <- c.maxConns
	ch <- c.constructing
	ch <- c.acquireCount
	ch <- c.acquireDuration
	ch <- c.emptyAcquire
}

func (c *DBCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.pool.Stat()

	ch <- prometheus.MustNewConstMetric(c.totalConns, prometheus.GaugeValue, float64(s.TotalConns()))
	ch <- prometheus.MustNewConstMetric(c.idleConns, prometheus.GaugeValue, float64(s.IdleConns()))
	ch <- prometheus.MustNewConstMetric(c.acquiredConns, prometheus.GaugeValue, float64(s.AcquiredConns()))
	ch <- prometheus.MustNewConstMetric(c.maxConns, prometheus.GaugeValue, float64(s.MaxConns()))
	ch <- prometheus.MustNewConstMetric(c.constructing, prometheus.GaugeValue, float64(s.ConstructingConns()))
	ch <- prometheus.MustNewConstMetric(c.acquireCount, prometheus.CounterValue, float64(s.AcquireCount()))
	ch <- prometheus.MustNewConstMetric(c.acquireDuration, prometheus.CounterValue, s.AcquireDuration().Seconds())
	ch <- prometheus.MustNewConstMetric(c.emptyAcquire, prometheus.CounterValue, float64(s.EmptyAcquireCount()))
}
