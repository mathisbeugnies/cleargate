// Package metrics exposes Prometheus counters for the proxy pipeline.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cleargate_requests_total",
		Help: "Proxied requests by policy verdict.",
	}, []string{"verdict"})

	requestDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "cleargate_request_duration_seconds",
		Help:    "End-to-end proxy request latency.",
		Buckets: prometheus.DefBuckets,
	})

	upstreamErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cleargate_upstream_errors_total",
		Help: "Failed calls to an upstream provider.",
	})
)

func init() {
	prometheus.MustRegister(requestsTotal, requestDuration, upstreamErrors)
}

// ObserveRequest records one completed proxy request.
func ObserveRequest(verdict string, seconds float64) {
	requestsTotal.WithLabelValues(verdict).Inc()
	requestDuration.Observe(seconds)
}

// ObserveUpstreamError records a failed upstream call.
func ObserveUpstreamError() { upstreamErrors.Inc() }

// Handler serves the Prometheus exposition endpoint.
func Handler() http.Handler { return promhttp.Handler() }
