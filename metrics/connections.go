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
)

// ConnectionTime gather the duration of a connection
func ConnectionTime(d time.Duration) {
	connDurationsHisto.Observe(d.Seconds())
}
