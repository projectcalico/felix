// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.
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

package wireguard_test

import (
	. "github.com/projectcalico/felix/wireguard"

	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	mocknetlink "github.com/projectcalico/felix/netlink/mock"
	mocktime "github.com/projectcalico/felix/time/mock"
)

var (
	zeroKey = wgtypes.Key{}
)

func mustGeneratePrivateKey() wgtypes.Key {
	key, err := wgtypes.GeneratePrivateKey()
	Expect(err).ToNot(HaveOccurred())
	return key
}

type mockStatus struct {
	numCallbacks int
	err          error
	key          wgtypes.Key
}

func (m *mockStatus) status(publicKey wgtypes.Key) error {
	log.Debugf("Status update with public key: %s", publicKey)
	m.numCallbacks++
	if m.err != nil {
		return m.err
	}
	m.key = publicKey

	log.Debugf("Num callbacks: %d", m.numCallbacks)
	return nil
}

var _ = Describe("Wireguard (enabled)", func() {
	var wgDataplane *mocknetlink.MockNetlinkDataplane
	var rtDataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var s *mockStatus
	var wg *Wireguard

	BeforeEach(func() {
		wgDataplane = mocknetlink.NewMockNetlinkDataplane()
		rtDataplane = mocknetlink.NewMockNetlinkDataplane()
		t = mocktime.NewMockTime()
		s = &mockStatus{}
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.SetAutoIncrement(11 * time.Second)

		wg = NewWithShims(
			"my-host",
			&Config{
				Enabled:             true,
				ListeningPort:       1000,
				FirewallMark:        10,
				RoutingRulePriority: 99,
				RoutingTableIndex:   99,
				InterfaceName:       "wireguard.cali",
				MTU:                 2000,
			},
			rtDataplane.NewMockNetlink,
			wgDataplane.NewMockNetlink,
			wgDataplane.NewMockWireguard,
			10*time.Second,
			t,
			0,
			s.status,
		)
	})

	It("should be constructable", func() {
		Expect(wg).ToNot(BeNil())
	})

	Describe("should handle creation of the wireguard link", func() {
		BeforeEach(func() {
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should configure the link but wait for link to be active", func() {
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
			Expect(wgDataplane.AddedLinks).To(HaveKey("wireguard.cali"))
			Expect(wgDataplane.NameToLink["wireguard.cali"].LinkType).To(Equal("wireguard"))
			Expect(wgDataplane.NameToLink["wireguard.cali"].LinkAttrs.MTU).To(Equal(2000))
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
			Expect(wgDataplane.WireguardOpen).To(BeFalse())
		})

		It("another apply will no-op until link is active", func() {
			// Apply, but still not iface update
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
			Expect(wgDataplane.WireguardOpen).To(BeFalse())
		})

		It("no op after a link down callback", func() {
			// Iface update indicating down.
			wg.OnIfaceStateChanged("wireguard.cali", ifacemonitor.StateUp)
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
			Expect(wgDataplane.WireguardOpen).To(BeFalse())
		})

		Describe("handle link up", func() {
			BeforeEach(func() {
				wgDataplane.SetIface("wireguard.cali", true, true)
				wg.OnIfaceStateChanged("wireguard.cali", ifacemonitor.StateUp)
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())
			})

			It("should create wireguard client and create private key", func() {
				Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
				link := wgDataplane.NameToLink["wireguard.cali"]
				Expect(link.WireguardFirewallMark).To(Equal(10))
				Expect(link.WireguardListenPort).To(Equal(1000))
				Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
				Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
				Expect(s.numCallbacks).To(Equal(1))
				Expect(s.key).To(Equal(link.WireguardPublicKey))
			})

			It("after endpoint update with incorrect key should program the interface address and resend same key as status", func() {
				link := wgDataplane.NameToLink["wireguard.cali"]
				Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
				Expect(s.numCallbacks).To(Equal(1))
				key := link.WireguardPrivateKey
				Expect(s.key).To(Equal(key.PublicKey()))

				ipv4 := ip.FromString("1.2.3.4")
				wg.EndpointWireguardUpdate("my-host", zeroKey, ipv4)
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())
				link = wgDataplane.NameToLink["wireguard.cali"]
				Expect(link.Addrs).To(HaveLen(1))
				Expect(link.Addrs[0].IP).To(Equal(ipv4.AsNetIP()))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
				Expect(link.WireguardFirewallMark).To(Equal(10))
				Expect(link.WireguardListenPort).To(Equal(1000))
				Expect(link.WireguardPrivateKey).To(Equal(key))
				Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
				Expect(s.numCallbacks).To(Equal(2))
				Expect(s.key).To(Equal(key.PublicKey()))
			})

			It("after endpoint update with correct key should program the interface address and not send another status update", func() {
				link := wgDataplane.NameToLink["wireguard.cali"]
				Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
				Expect(s.numCallbacks).To(Equal(1))
				key := link.WireguardPrivateKey

				ipv4 := ip.FromString("1.2.3.4")
				wg.EndpointWireguardUpdate("my-host", key.PublicKey(), ipv4)
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())
				link = wgDataplane.NameToLink["wireguard.cali"]
				Expect(link.Addrs).To(HaveLen(1))
				Expect(link.Addrs[0].IP).To(Equal(ipv4.AsNetIP()))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
				Expect(link.WireguardFirewallMark).To(Equal(10))
				Expect(link.WireguardListenPort).To(Equal(1000))
				Expect(link.WireguardPrivateKey).To(Equal(key))
				Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
				Expect(s.numCallbacks).To(Equal(1))
			})

			Describe("should handle two wireguard peers with different public keys", func() {
				var ipv4_1, ipv4_2 ip.Addr
				var key_1, key_2 wgtypes.Key
				var link *mocknetlink.MockLink
				BeforeEach(func() {
					Expect(s.numCallbacks).To(Equal(1))
					wg.EndpointWireguardUpdate("my-host", s.key, nil)
					ipv4_1 = ip.FromString("1.2.3.5")
					key_1 = mustGeneratePrivateKey()
					wg.EndpointWireguardUpdate("peer1", key_1, nil)
					wg.EndpointUpdate("peer1", ipv4_1)
					ipv4_2 = ip.FromString("1.2.3.6")
					key_2 = mustGeneratePrivateKey()
					wg.EndpointWireguardUpdate("peer2", key_2, nil)
					wg.EndpointUpdate("peer2", ipv4_2)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					link = wgDataplane.NameToLink["wireguard.cali"]
					Expect(link).ToNot(BeNil())
					Expect(wgDataplane.WireguardOpen).To(BeTrue())
					Expect(link.WireguardFirewallMark).To(Equal(10))
					Expect(link.WireguardListenPort).To(Equal(1000))
					Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
					Expect(wgDataplane.NumRuleDelCalls).To(Equal(0))
					Expect(wgDataplane.NumRuleAddCalls).To(Equal(1))
				})

				It("should have both peers configured", func() {
					Expect(link.WireguardPeers).To(HaveLen(2))
					Expect(link.WireguardPeers).To(HaveKey(key_1))
					Expect(link.WireguardPeers).To(HaveKey(key_2))
					Expect(link.WireguardPeers[key_1]).To(Equal(wgtypes.Peer{
						PublicKey: key_1,
						Endpoint: &net.UDPAddr{
							IP: ipv4_1.AsNetIP(),
							Port: 1000,
						},
					}))
					Expect(link.WireguardPeers[key_2]).To(Equal(wgtypes.Peer{
						PublicKey: key_2,
						Endpoint: &net.UDPAddr{
							IP: ipv4_2.AsNetIP(),
							Port: 1000,
						},
					}))
				})

				It("should remove both peers if public keys updated to conflict", func() {
					wg.EndpointWireguardUpdate("peer2", key_1, nil)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(link.WireguardPeers).To(HaveLen(0))
					Expect(wgDataplane.NumRuleAddCalls).To(Equal(1))
				})

				It("should add both peers if conflicting public keys updated to no longer conflict", func() {
					wg.EndpointWireguardUpdate("peer2", key_1, nil)
					err := wg.Apply()
					wg.EndpointWireguardUpdate("peer2", key_2, nil)
					err = wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(link.WireguardPeers).To(HaveKey(key_1))
					Expect(link.WireguardPeers).To(HaveKey(key_2))
					Expect(link.WireguardPeers[key_1]).To(Equal(wgtypes.Peer{
						PublicKey: key_1,
						Endpoint: &net.UDPAddr{
							IP: ipv4_1.AsNetIP(),
							Port: 1000,
						},
					}))
					Expect(link.WireguardPeers[key_2]).To(Equal(wgtypes.Peer{
						PublicKey: key_2,
						Endpoint: &net.UDPAddr{
							IP: ipv4_2.AsNetIP(),
							Port: 1000,
						},
					}))
					Expect(wgDataplane.NumRuleAddCalls).To(Equal(1))
				})
			})
		})
	})

	It("should create wireguard client if link activates immediately", func() {
		wgDataplane.ImmediateLinkUp = true
		err := wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
		Expect(wgDataplane.WireguardOpen).To(BeTrue())
	})

	It("should create wireguard client and not attempt to create the link if link is already up", func() {
		wgDataplane.AddIface(10, "wireguard.cali", true, true)
		err := wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplane.WireguardOpen).To(BeTrue())
	})

	It("should update listen port and firewall mark but maintain correct key", func() {
		key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		wgDataplane.AddIface(10, "wireguard.cali", true, true)
		link := wgDataplane.NameToLink["wireguard.cali"]
		Expect(link).ToNot(BeNil())
		link.WireguardPrivateKey = key
		link.WireguardPublicKey = key.PublicKey()
		link.WireguardListenPort = 1010
		link.WireguardFirewallMark = 11

		ipv4 := ip.FromString("1.2.3.4")
		wg.EndpointWireguardUpdate("my-host", key, ipv4)

		err = wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplane.WireguardOpen).To(BeTrue())

		link = wgDataplane.NameToLink["wireguard.cali"]
		Expect(link).ToNot(BeNil())
		Expect(link.Addrs).To(HaveLen(1))
		Expect(link.Addrs[0].IP).To(Equal(ipv4.AsNetIP()))
		Expect(wgDataplane.WireguardOpen).To(BeTrue())
		Expect(link.WireguardFirewallMark).To(Equal(10))
		Expect(link.WireguardListenPort).To(Equal(1000))
		Expect(link.WireguardPrivateKey).To(Equal(key))
		Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
		Expect(s.numCallbacks).To(Equal(1))
	})
})

var _ = Describe("Wireguard (disabled)", func() {
	var wgDataplane *mocknetlink.MockNetlinkDataplane
	var rtDataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var s mockStatus
	var wg *Wireguard

	BeforeEach(func() {
		wgDataplane = mocknetlink.NewMockNetlinkDataplane()
		rtDataplane = mocknetlink.NewMockNetlinkDataplane()
		t = mocktime.NewMockTime()
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.SetAutoIncrement(11 * time.Second)

		wg = NewWithShims(
			"my-host",
			&Config{
				Enabled:             false,
				ListeningPort:       1000,
				FirewallMark:        1,
				RoutingRulePriority: 99,
				RoutingTableIndex:   99,
				InterfaceName:       "wireguard.cali",
				MTU:                 1042,
			},
			rtDataplane.NewMockNetlink,
			wgDataplane.NewMockNetlink,
			wgDataplane.NewMockWireguard,
			10*time.Second,
			t,
			0,
			s.status,
		)
	})

	It("should be constructable", func() {
		Expect(wg).ToNot(BeNil())
	})

	It("should handle deletion of the wireguard link", func() {
		Expect(wg).ToNot(BeNil())
		wgDataplane.AddIface(1, "wireguard.cali", true, true)
		err := wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkDeleteCalls).To(Equal(1))
		Expect(wgDataplane.DeletedLinks).To(HaveKey("wireguard.cali"))
	})
})
