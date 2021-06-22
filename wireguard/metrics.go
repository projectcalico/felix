// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wireguard

import (
	"fmt"
	"os"

	"github.com/projectcalico/felix/netlinkshim"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	labelHostname      = "hostname"
	labelPublicKey     = "public_key"
	labelInterfaceName = "iface"
	labelListenPort    = "listen_port"
	labelPeerKey       = "peer_key"
	labelPeerEndpoint  = "peer_endpoint"
)

var _ prometheus.Collector = (*Metrics)(nil)

const (
	wireguardMetaFQName   = "wireguard_meta"
	wireguardMetaHelpText = "wireguard interface and runtime metadata"

	wireguardLatestHandshakeIntervalFQName   = "wireguard_latest_handshake_seconds"
	wireguardLatestHandshakeIntervalHelpText = "wireguard interface latest handshake unix timestamp in seconds to a peer"

	wireguardBytesSentFQName   = "wireguard_bytes_sent_total"
	wireguardBytesSentHelpText = "wireguard interface total outgoing bytes to peer"

	wireguardBytesRcvdFQName   = "wireguard_bytes_rcvd_total"
	wireguardBytesRcvdHelpText = "wireguard interface total incoming bytes to peer"
)

func init() {
	prometheus.MustRegister(
		MustNewWireguardMetrics(),
	)
}

type Metrics struct {
	hostname           string
	newWireguardClient func() (netlinkshim.Wireguard, error)
	logCtx             *logrus.Entry

	peerRx, peerTx map[wgtypes.Key]int64
}

func (collector *Metrics) Describe(chan<- *prometheus.Desc) {}

func (collector *Metrics) Collect(m chan<- prometheus.Metric) {
	collector.refreshStats(m)
}

func MustNewWireguardMetrics() *Metrics {
	wg, err := NewWireguardMetrics()
	if err != nil {
		logrus.Panic(err)
	}
	return wg
}

func NewWireguardMetrics() (*Metrics, error) {
	hostname, err := os.Hostname()
	if err != nil {
		logrus.WithError(err).Error("cannot register wireguard metrics stats")
		return nil, err
	}
	return NewWireguardMetricsWithShims(hostname, netlinkshim.NewRealWireguard), nil
}

func NewWireguardMetricsWithShims(hostname string, newWireguardClient func() (netlinkshim.Wireguard, error)) *Metrics {
	logrus.WithField("hostname", hostname).Debug("created wireguard collector for host")
	return &Metrics{
		hostname:           hostname,
		newWireguardClient: newWireguardClient,
		logCtx: logrus.WithFields(logrus.Fields{
			"prometheus_collector": "wireguard",
		}),

		peerRx: map[wgtypes.Key]int64{},
		peerTx: map[wgtypes.Key]int64{},
	}
}

func (collector *Metrics) refreshStats(m chan<- prometheus.Metric) {
	wgClient, err := collector.newWireguardClient()
	if err != nil {
		collector.logCtx.WithError(err).Error("error initializing wireguard client devices")
		return
	}

	devices, err := wgClient.Devices()
	if err != nil {
		collector.logCtx.WithError(err).Error("error listing wireguard devices")
		return
	}
	collector.logCtx.WithFields(logrus.Fields{
		"count": len(devices),
		"dev":   devices,
	}).Debug("collect device metrics enumerated devices")

	collector.collectDeviceMetrics(devices, m)
	collector.collectDevicePeerMetrics(devices, m)
}

func (collector *Metrics) collectDeviceMetrics(devices []*wgtypes.Device, m chan<- prometheus.Metric) {
	collector.logCtx.Debug("collecting wg device metrics")

	for _, device := range devices {
		l := collector.defaultLabelValues(device.PublicKey.String())
		for k, v := range deviceMetaLabelValues(device) {
			l[k] = v
		}
		collector.logCtx.WithFields(logrus.Fields{
			"dev":    device.Name,
			"labels": l,
		}).Debug("iterate device")

		m <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				wireguardMetaFQName, wireguardMetaHelpText, nil, l,
			),
			prometheus.GaugeValue,
			1,
		)
	}
}

func (collector *Metrics) collectDevicePeerMetrics(devices []*wgtypes.Device, m chan<- prometheus.Metric) {
	collector.logCtx.Debug("collecting wg peer(s) metrics")

	collector.logCtx.WithFields(logrus.Fields{
		"count": len(devices),
	}).Debug("enumerated wireguard devices")

	for _, device := range devices {
		labels := collector.defaultLabelValues(device.PublicKey.String())
		logCtx := collector.logCtx.WithFields(logrus.Fields{
			"key":  device.PublicKey,
			"name": device.Name,
		})
		for _, peer := range device.Peers {
			logCtx.WithFields(logrus.Fields{
				"peer_key":      peer.PublicKey,
				"peer_endpoint": peer.Endpoint,
			}).Debug("collect peer metrics")

			serviceLabelValues := peerServiceLabelValues(&peer)
			for k, v := range serviceLabelValues {
				labels[k] = v
			}

			hs := float64(peer.LastHandshakeTime.Unix())

			collector.logCtx.WithFields(logrus.Fields{
				"rx_bytes_total":     peer.ReceiveBytes,
				"tx_bytes_total":     peer.TransmitBytes,
				"handshake_ts": hs,
			}).Debug("collected peer metrics")

			m <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					wireguardBytesRcvdFQName, wireguardBytesRcvdHelpText, nil, labels,
				),
				prometheus.CounterValue,
				float64(peer.ReceiveBytes),
			)

			m <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					wireguardBytesSentFQName, wireguardBytesSentHelpText, nil, labels,
				),
				prometheus.CounterValue,
				float64(peer.TransmitBytes),
			)

			m <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					wireguardLatestHandshakeIntervalFQName, wireguardLatestHandshakeIntervalHelpText, nil, labels,
				),
				prometheus.GaugeValue,
				hs,
			)
		}
	}

}

func (collector *Metrics) defaultLabelValues(publicKey string) prometheus.Labels {
	l := prometheus.Labels{labelHostname: collector.hostname}
	if publicKey != "" {
		l[labelPublicKey] = publicKey
	}
	return l
}

func deviceMetaLabelValues(dev *wgtypes.Device) prometheus.Labels {
	return prometheus.Labels{
		labelInterfaceName: dev.Name,
		labelListenPort:    fmt.Sprintf("%d", dev.ListenPort),
	}
}

func peerServiceLabelValues(peer *wgtypes.Peer) prometheus.Labels {
	return prometheus.Labels{
		labelPeerKey:      peer.PublicKey.String(),
		labelPeerEndpoint: peer.Endpoint.String(),
	}
}
