package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	connDurationsHisto = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "connection_durations_histogram_seconds",
		Help: "Connection duration distributions.",
	})
	connCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "connections_total",
			Help: "How many TCP connections are opened",
		},
	)
)

// IncConnections increments the total connections counter
func IncConnections() {
	connCounter.Inc()
}

// ConnectionTime gather the duration of a connection
func ConnectionTime(d time.Duration) {
	connDurationsHisto.Observe(d.Seconds())
}
