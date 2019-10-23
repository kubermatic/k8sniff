package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	Prefix = "k8sniff_"
)

func init() {
	prometheus.MustRegister(connDurationsHisto)
	prometheus.MustRegister(connGauge)
	prometheus.MustRegister(backendConnGauge)
	prometheus.MustRegister(backendBytesSentCtr)
	prometheus.MustRegister(backendBytesRcvdCtr)
	prometheus.MustRegister(errorCounterVec)
	prometheus.MustRegister(backendGauge)
	prometheus.MustRegister(teardownDurationsHisto)
	prometheus.MustRegister(bytesCopiedHisto)
	prometheus.MustRegister(teardownTimeoutCtr)
}
