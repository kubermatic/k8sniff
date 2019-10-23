package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	backendGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: Prefix + "configured_backends_count",
			Help: "Number of configured backends",
		},
	)
	backendBytesSentCtr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: Prefix + "backend_bytes_sent_total",
			Help: "Number of bytes sent to a given backend",
		},
		[]string{"backend"},
	)
	backendBytesRcvdCtr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: Prefix + "backend_bytes_received_total",
			Help: "Number of bytes received from a given backend",
		},
		[]string{"backend"},
	)
)

func SetBackendCount(count int) {
	backendGauge.Set(float64(count))
}

// AddBackendBytesSent adds the total bytes relayed from k8sniff to the
// given backend
func AddBackendBytesSent(backend string, numBytes int64) {
	g, _ := backendBytesSentCtr.GetMetricWithLabelValues(backend)
	g.Add(float64(numBytes))
}

// AddBackendBytesRcvd adds the total bytes copied from the given backend
// to the client
func AddBackendBytesRcvd(backend string, numBytes int64) {
	g, _ := backendBytesRcvdCtr.GetMetricWithLabelValues(backend)
	g.Add(float64(numBytes))
}

