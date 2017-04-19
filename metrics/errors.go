package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	Error = "error"
	Fatal = "fatal"
	Info  = "info"
)

var (
	errorCounterVec = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "errors_total",
			Help: "Total error count, partitioned by error type.",
		},
		[]string{"type"},
	)
)

// IncErrors increments the total errors counter
func IncErrors(typ string) {
	errorCounterVec.WithLabelValues(typ).Inc()
}
