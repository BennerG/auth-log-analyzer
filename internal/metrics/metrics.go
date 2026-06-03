package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequestsTotal counts requests by method, path, and status code
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_analyzer_http_requests_total",
			Help: "Total number of HTTP requests by method, path, and status code",
		},
		[]string{"method", "path", "status"},
	)

	// HTTPRequestDuration tracks request latency as a histogram
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_analyzer_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets, // .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10
		},
		[]string{"method", "path"},
	)

	// AuthEventsIngested counts auth events by type and status
	AuthEventsIngested = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_analyzer_events_ingested_total",
			Help: "Total number of auth events ingested by event_type and status",
		},
		[]string{"event_type", "status"},
	)
)
