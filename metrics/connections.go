package metrics

import (
	"time"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	connDurationsHisto = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: Prefix + "connection_durations_histogram_seconds",
		Help: "Connection duration distributions.",
	})
	connGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: Prefix + "opened_connections_count",
			Help: "Number of opened TCP connections",
		},
	)
	backendConnGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: Prefix + "opened_backend_connections_count",
			Help: "Number of established backend TCP connections",
		},
		[]string{"backend"},
	)
	teardownDurationsHisto = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: Prefix + "teardown_durations_histogram_seconds",
		Help: "Connection teardown duration distributions.",
		Buckets: []float64{1.0, 2.0, 4.0, 8.0, 16.0, 32.0},
	})
	bytesCopiedHisto = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: Prefix + "bytes_copied_histogram",
		Help: "Bytes copied distributions.",
		Buckets: []float64{1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0},
	})
	teardownTimeoutCtr = prometheus.NewCounter(prometheus.CounterOpts{
		Name: Prefix + "teardown_timeouts",
		Help: "Number of connection teardown timeouts.",
	})
)

// IncConnections increments the total connections counter
func IncConnections() {
	connGauge.Inc()
}

func DecConnections() {
	connGauge.Dec()
}

// IncBackendConnections increments the total connections currently established
// for a given backend
func IncBackendConnections(backend string) {
	g, _ := backendConnGauge.GetMetricWithLabelValues(backend)
	g.Inc()
}

func DecBackendConnections(backend string) {
	g, _ := backendConnGauge.GetMetricWithLabelValues(backend)
	g.Dec()
}

// ConnectionTime gather the duration of a connection
func ConnectionTime(d time.Duration) {
	connDurationsHisto.Observe(d.Seconds())
}

func TeardownTime(d time.Duration) {
	teardownDurationsHisto.Observe(d.Seconds())
}

func BytesCopied(bytes int64) {
	bytesCopiedHisto.Observe(float64(bytes))
}

func TeardownTimeout() {
	teardownTimeoutCtr.Inc()
}
