package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tigerfetch_http_requests_total",
	Help: "HTTP requests by path and status code.",
}, []string{"path", "status_code"})

var httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "tigerfetch_http_request_duration_seconds",
	Help:    "HTTP request duration by path.",
	Buckets: prometheus.DefBuckets,
}, []string{"path"})

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// InstrumentHandler wraps an http.Handler with request count and duration metrics.
func InstrumentHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		httpRequests.WithLabelValues(r.URL.Path, strconv.Itoa(rw.status)).Inc()
		httpDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	})
}
