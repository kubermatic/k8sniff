package metrics

import "github.com/prometheus/client_golang/prometheus"

func init() {
	prometheus.MustRegister(connDurationsHisto)
	prometheus.MustRegister(connGauge)
	prometheus.MustRegister(errorCounterVec)
}
