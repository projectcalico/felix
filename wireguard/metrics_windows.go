package wireguard

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {}

func MustNewWireguardMetrics() *Metrics {
	return &Metrics{}
}

func (collector *Metrics) Describe(d chan<- *prometheus.Desc) {}
func (collector *Metrics) Collect(m chan<- prometheus.Metric) {}
