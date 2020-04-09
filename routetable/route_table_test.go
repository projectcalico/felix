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

package routetable_test

import (
	. "github.com/projectcalico/felix/routetable"

	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/testutils"
	"github.com/projectcalico/libcalico-go/lib/set"
)

var (
	FelixRouteProtocol = syscall.RTPROT_BOOT

	simulatedError = errors.New("dummy error")
	notFound       = errors.New("not found")
	alreadyExists  = errors.New("already exists")

	mac1 = testutils.MustParseMAC("00:11:22:33:44:51")
	mac2 = testutils.MustParseMAC("00:11:22:33:44:52")

	ip1  = ip.MustParseCIDROrIP("10.0.0.1/32").ToIPNet()
	ip2  = ip.MustParseCIDROrIP("10.0.0.2/32").ToIPNet()
	ip13 = ip.MustParseCIDROrIP("10.0.1.3/32").ToIPNet()
)

var _ = Describe("RouteTable v6", func() {
	var dataplane *mockDataplane
	var t *mockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = &mockDataplane{
			nameToLink:       map[string]netlink.Link{},
			routeKeyToRoute:  map[string]netlink.Route{},
			addedRouteKeys:   set.New(),
			deletedRouteKeys: set.New(),
			updatedRouteKeys: set.New(),
		}
		startTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		Expect(err).NotTo(HaveOccurred())
		t = &mockTime{
			currentTime: startTime,
		}
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.setAutoIncrement(11 * time.Second)
		rt = NewWithShims(
			[]string{"cali"}, true,
			6,
			dataplane.NewNetlinkHandle,
			false,
			10*time.Second,
			dataplane.AddStaticArpEntry,
			dataplane,
			t,
			nil,
			FelixRouteProtocol,
			true,
			0,
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	It("should not remove the IPv6 link local route", func() {
		// Route that should be left alone
		noopLink := dataplane.addIface(4, "cali4", true, true)
		noopRoute := netlink.Route{
			LinkIndex: noopLink.attrs.Index,
			Dst:       mustParseCIDR("fe80::/64"),
			Type:      syscall.RTN_UNICAST,
			Protocol:  syscall.RTPROT_KERNEL,
			Scope:     netlink.SCOPE_LINK,
		}
		rt.SetRoutes(noopLink.attrs.Name, []Target{
			{CIDR: ip.MustParseCIDROrIP("10.0.0.4/32"), DestMAC: mac1},
		})
		dataplane.addMockRoute(&noopRoute)

		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.deletedRouteKeys).ToNot(HaveKey(keyForRoute(&noopRoute)))
		Expect(dataplane.updatedRouteKeys).ToNot(HaveKey(keyForRoute(&noopRoute)))
	})
})

var _ = Describe("RouteTable", func() {
	var dataplane *mockDataplane
	var t *mockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = &mockDataplane{
			nameToLink:       map[string]netlink.Link{},
			routeKeyToRoute:  map[string]netlink.Route{},
			addedRouteKeys:   set.New(),
			deletedRouteKeys: set.New(),
			updatedRouteKeys: set.New(),
		}
		startTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		Expect(err).NotTo(HaveOccurred())
		t = &mockTime{
			currentTime: startTime,
		}
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.setAutoIncrement(11 * time.Second)
		rt = NewWithShims(
			[]string{"cali"}, true,
			4,
			dataplane.NewNetlinkHandle,
			false,
			10*time.Second,
			dataplane.AddStaticArpEntry,
			dataplane,
			t,
			nil,
			FelixRouteProtocol,
			true,
			0,
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	It("should handle unexpected non-calico interface updates", func() {
		t.setAutoIncrement(0 * time.Second)
		rt.OnIfaceStateChanged("calx", ifacemonitor.StateUp)
		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
	})

	It("should handle unexpected calico interface updates", func() {
		t.setAutoIncrement(0 * time.Second)
		rt.OnIfaceStateChanged("cali1", ifacemonitor.StateUp)
		rt.QueueResync()
		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
		t.incrementTime(11 * time.Second)
		rt.QueueResync()
		err = rt.Apply()
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("with some interfaces", func() {
		var cali1, cali3, eth0 *mockLink
		var gatewayRoute, cali1Route, cali1Route2, cali3Route netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.addIface(0, "eth0", true, true)
			cali1 = dataplane.addIface(1, "cali1", true, true)
			dataplane.addIface(2, "cali2", true, true)
			cali3 = dataplane.addIface(3, "cali3", true, true)
			cali1Route = netlink.Route{
				LinkIndex: cali1.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&cali1Route)
			cali3Route = netlink.Route{
				LinkIndex: cali3.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&cali3Route)
			gatewayRoute = netlink.Route{
				LinkIndex: eth0.attrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
			}
			dataplane.addMockRoute(&gatewayRoute)
		})
		It("should wait for the route cleanup delay", func() {
			t.setAutoIncrement(0 * time.Second)
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route, cali3Route, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
			t.incrementTime(11 * time.Second)
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should wait for the route cleanup delay when resyncing", func() {
			t.setAutoIncrement(0 * time.Second)
			rt.QueueResync()
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route, cali3Route, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
			t.incrementTime(11 * time.Second)
			rt.QueueResync()
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should clean up only our routes", func() {
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should delete only our conntrack entries", func() {
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Eventually(dataplane.GetDeletedConntrackEntries).Should(ConsistOf(
				net.ParseIP("10.0.0.1").To4(),
				net.ParseIP("10.0.0.3").To4(),
			))
		})
		It("Should clear out a source address when source address is not set", func() {
			updateLink := dataplane.addIface(5, "cali5", true, true)
			updateRoute := netlink.Route{
				LinkIndex: updateLink.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.5/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Src:       net.ParseIP("192.168.0.1"),
			}
			dataplane.addMockRoute(&updateRoute)
			rt.SetRoutes(updateLink.attrs.Name, []Target{
				{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
			})

			fixedRoute := updateRoute
			fixedRoute.Src = nil

			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.updatedRouteKeys).To(HaveKey(keyForRoute(&updateRoute)))
			Expect(dataplane.routeKeyToRoute[keyForRoute(&updateRoute)]).To(Equal(fixedRoute))

		})
		Describe("With a device route source address set", func() {
			deviceRouteSource := "192.168.0.1"
			deviceRouteSourceAddress := net.ParseIP(deviceRouteSource)
			// Modify the route table to have the device route source address set
			BeforeEach(func() {
				rt = NewWithShims(
					[]string{"cali"}, true,
					4,
					dataplane.NewNetlinkHandle,
					false,
					10*time.Second,
					dataplane.AddStaticArpEntry,
					dataplane,
					t,
					deviceRouteSourceAddress,
					FelixRouteProtocol,
					true,
					0,
				)
			})
			It("Should delete routes without a source address", func() {
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.deletedRouteKeys).To(HaveKey(keyForRoute(&cali3Route)))
				Expect(dataplane.deletedRouteKeys).To(HaveKey(keyForRoute(&cali1Route)))
			})
			It("Should add routes with a source address", func() {
				// Route that needs to be added
				addLink := dataplane.addIface(6, "cali6", true, true)
				rt.SetRoutes(addLink.attrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.6"), DestMAC: mac1},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.routeKeyToRoute["254-6-10.0.0.6/32"]).To(Equal(netlink.Route{
					LinkIndex: addLink.attrs.Index,
					Dst:       mustParseCIDR("10.0.0.6/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       deviceRouteSourceAddress,
				}))
			})
			It("Should not remove routes with a source address", func() {
				// Route that should be left alone
				noopLink := dataplane.addIface(4, "cali4", true, true)
				noopRoute := netlink.Route{
					LinkIndex: noopLink.attrs.Index,
					Dst:       mustParseCIDR("10.0.0.4/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       deviceRouteSourceAddress,
				}
				rt.SetRoutes(noopLink.attrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.4/32"), DestMAC: mac1},
				})
				dataplane.addMockRoute(&noopRoute)

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.deletedRouteKeys).ToNot(HaveKey(keyForRoute(&noopRoute)))
				Expect(dataplane.updatedRouteKeys).ToNot(HaveKey(keyForRoute(&noopRoute)))
			})
			It("Should update source addresses from nil to a given source", func() {
				// Route that needs to be updated
				updateLink := dataplane.addIface(5, "cali5", true, true)
				updateRoute := netlink.Route{
					LinkIndex: updateLink.attrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}
				rt.SetRoutes(updateLink.attrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
				})
				dataplane.addMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Src = deviceRouteSourceAddress

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.updatedRouteKeys).To(HaveKey(keyForRoute(&updateRoute)))
				Expect(dataplane.routeKeyToRoute[keyForRoute(&updateRoute)]).To(Equal(fixedRoute))
			})

			It("Should update source addresses from an old source to a new one", func() {
				// Route that needs to be updated
				updateLink := dataplane.addIface(5, "cali5", true, true)
				updateRoute := netlink.Route{
					LinkIndex: updateLink.attrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       net.ParseIP("192.168.0.2"),
				}
				rt.SetRoutes(updateLink.attrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
				})
				dataplane.addMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Src = deviceRouteSourceAddress

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.updatedRouteKeys).To(HaveKey(keyForRoute(&updateRoute)))
				Expect(dataplane.routeKeyToRoute[keyForRoute(&updateRoute)]).To(Equal(fixedRoute))
			})
		})

		Describe("With a device route protocol set", func() {
			deviceRouteProtocol := 10
			// Modify the route table to have the device route source address set
			BeforeEach(func() {
				rt = NewWithShims(
					[]string{"cali"}, true,
					4,
					dataplane.NewNetlinkHandle,
					false,
					10*time.Second,
					dataplane.AddStaticArpEntry,
					dataplane,
					t,
					nil,
					deviceRouteProtocol,
					true,
					0,
				)
			})
			It("Should delete routes without a protocol", func() {
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.deletedRouteKeys).To(HaveKey(keyForRoute(&cali3Route)))
				Expect(dataplane.deletedRouteKeys).To(HaveKey(keyForRoute(&cali1Route)))
			})
			It("Should add routes with a protocol", func() {
				// Route that needs to be added
				addLink := dataplane.addIface(6, "cali6", true, true)
				rt.SetRoutes(addLink.attrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.6"), DestMAC: mac1},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.routeKeyToRoute["254-6-10.0.0.6/32"]).To(Equal(netlink.Route{
					LinkIndex: addLink.attrs.Index,
					Dst:       mustParseCIDR("10.0.0.6/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})
			It("Should not remove routes with a protocol", func() {
				// Route that should be left alone
				noopLink := dataplane.addIface(4, "cali4", true, true)
				noopRoute := netlink.Route{
					LinkIndex: noopLink.attrs.Index,
					Dst:       mustParseCIDR("10.0.0.4/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}
				rt.SetRoutes(noopLink.attrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.4/32"), DestMAC: mac1},
				})
				dataplane.addMockRoute(&noopRoute)

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.deletedRouteKeys).ToNot(HaveKey(keyForRoute(&noopRoute)))
				Expect(dataplane.updatedRouteKeys).ToNot(HaveKey(keyForRoute(&noopRoute)))
			})
			It("Should update protocol from nil to a given protocol", func() {
				// Route that needs to be updated
				updateLink := dataplane.addIface(5, "cali5", true, true)
				updateRoute := netlink.Route{
					LinkIndex: updateLink.attrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Scope:     netlink.SCOPE_LINK,
				}
				rt.SetRoutes(updateLink.attrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
				})
				dataplane.addMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Protocol = deviceRouteProtocol

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.updatedRouteKeys).To(HaveKey(keyForRoute(&updateRoute)))
				Expect(dataplane.routeKeyToRoute[keyForRoute(&updateRoute)]).To(Equal(fixedRoute))
			})

			It("Should update protocol from an old protocol to a new one", func() {
				// Route that needs to be updated
				updateLink := dataplane.addIface(5, "cali5", true, true)
				updateRoute := netlink.Route{
					LinkIndex: updateLink.attrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  64,
					Scope:     netlink.SCOPE_LINK,
				}
				rt.SetRoutes(updateLink.attrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
				})
				dataplane.addMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Protocol = deviceRouteProtocol

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.updatedRouteKeys).To(HaveKey(keyForRoute(&updateRoute)))
				Expect(dataplane.routeKeyToRoute[keyForRoute(&updateRoute)]).To(Equal(fixedRoute))
			})
		})

		Describe("with a slow conntrack deletion", func() {
			const delay = 300 * time.Millisecond
			BeforeEach(func() {
				dataplane.ConntrackSleep = delay
			})
			It("should block a route add until conntrack finished", func() {
				// Initial apply starts a background thread to delete
				// 10.0.0.1 and 10.0.0.3.
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// We try to add 10.0.0.1 back in.
				rt.SetRoutes("cali1", []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.1/32"), DestMAC: mac1},
				})
				start := time.Now()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(time.Since(start)).To(BeNumerically(">=", delay*9/10))
			})
			It("should not block an unrelated route add ", func() {
				// Initial apply starts a background thread to delete
				// 10.0.0.1 and 10.0.0.3.
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// We try to add 10.0.0.10, which hasn't been seen before.
				rt.SetRoutes("cali1", []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.10/32"), DestMAC: mac1},
				})
				start := time.Now()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(time.Since(start)).To(BeNumerically("<", delay/2))
			})
		})

		Describe("with a persistent failure to connect", func() {
			BeforeEach(func() {
				dataplane.PersistentlyFailToConnect = true
			})

			It("should panic after all its retries are exhausted", func() {
				for i := 0; i < 3; i++ {
					Expect(rt.Apply()).To(Equal(ConnectFailed))
				}
				Expect(func() { _ = rt.Apply() }).To(Panic())
			})
		})

		Describe("after syncing, after adding a route and failing the update twice", func() {
			JustBeforeEach(func() {
				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())

				dataplane.failuresToSimulate = failNextRouteAdd
				dataplane.persistFailures = true
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.20.30.40"),
				})
				err = rt.Apply()
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(UpdateFailed))

				dataplane.failuresToSimulate = 0
				dataplane.persistFailures = false
			})

			It("has not programmed the route", func() {
				Expect(dataplane.routeKeyToRoute).NotTo(ContainElement(netlink.Route{
					LinkIndex: cali3.attrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})

			It("resolves on the next apply", func() {
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(dataplane.routeKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.attrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})
		})

		Describe("after adding two routes to cali3", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.20.30.40"),
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.0.20.0/24"),
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should have two routes for cali3", func() {
				Expect(dataplane.routeKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.attrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.routeKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.attrs.Index,
					Dst:       mustParseCIDR("10.0.20.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})

			It("should make no dataplane updates when deleting, creating and updating back to the same target before the next apply", func() {
				rt.RouteRemove("cali3", ip.MustParseCIDROrIP("10.0.20.0/24"))
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.0.20.0/24"),
					GW:   ip.FromString("1.2.3.4"),
				})
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.0.20.0/24"),
				})
				dataplane.addedRouteKeys = set.New()
				dataplane.deletedRouteKeys = set.New()
				dataplane.updatedRouteKeys = set.New()

				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(dataplane.addedRouteKeys).To(BeEmpty())
				Expect(dataplane.deletedRouteKeys).To(BeEmpty())
				Expect(dataplane.updatedRouteKeys).To(BeEmpty())

				Expect(dataplane.routeKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.attrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.routeKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.attrs.Index,
					Dst:       mustParseCIDR("10.0.20.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})

			It("should make no dataplane updates when deleting and then setting back to the same target before the next apply", func() {
				rt.RouteRemove("cali3", ip.MustParseCIDROrIP("10.0.20.0/24"))
				rt.SetRoutes("cali3", []Target{{
					CIDR: ip.MustParseCIDROrIP("10.0.20.0/24"),
				}, {
					CIDR: ip.MustParseCIDROrIP("10.20.30.40"),
				}})

				dataplane.addedRouteKeys = set.New()
				dataplane.deletedRouteKeys = set.New()
				dataplane.updatedRouteKeys = set.New()

				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(dataplane.addedRouteKeys).To(BeEmpty())
				Expect(dataplane.deletedRouteKeys).To(BeEmpty())
				Expect(dataplane.updatedRouteKeys).To(BeEmpty())

				Expect(dataplane.routeKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.attrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.routeKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.attrs.Index,
					Dst:       mustParseCIDR("10.0.20.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})
		})

		// We do the following tests in different failure (and non-failure) scenarios.  In
		// each case, we make the failure transient so that only the first Apply() should
		// fail.  Then, at most, the second call to Apply() should succeed.
		for _, failFlags := range failureScenarios {
			failFlags := failFlags
			desc := fmt.Sprintf("with some routes added and failures: %v", failFlags)
			Describe(desc, func() {
				BeforeEach(func() {
					rt.SetRoutes("cali1", []Target{
						{CIDR: ip.MustParseCIDROrIP("10.0.0.1/32"), DestMAC: mac1},
					})
					rt.SetRoutes("cali2", []Target{
						{CIDR: ip.MustParseCIDROrIP("10.0.0.2/32"), DestMAC: mac2},
					})
					rt.SetRoutes("cali3", []Target{
						{CIDR: ip.MustParseCIDROrIP("10.0.1.3/32")},
					})
					dataplane.failuresToSimulate = failFlags
				})
				JustBeforeEach(func() {
					maxTries := 1
					if failFlags != 0 {
						maxTries = 2
					}
					for try := 0; try < maxTries; try++ {
						err := rt.Apply()
						if err == nil {
							// We should only need to retry if Apply returns an error.
							log.Info("Apply returned no error, breaking out of loop")
							break
						}
					}
					if failFlags == failNextLinkByNameNotFound {
						// Special case: a "not found" error doesn't get
						// rechecked straight away because it's expected
						// so we have to give the RouteTable a nudge.
						rt.QueueResync()
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
					}
				})
				It("should have consumed all failures", func() {
					// Check that all the failures we simulated were hit.
					Expect(dataplane.failuresToSimulate).To(Equal(failNone))
				})
				It("should keep correct route", func() {
					Expect(dataplane.routeKeyToRoute["254-1-10.0.0.1/32"]).To(Equal(netlink.Route{
						LinkIndex: 1,
						Dst:       &ip1,
						Type:      syscall.RTN_UNICAST,
						Protocol:  FelixRouteProtocol,
						Scope:     netlink.SCOPE_LINK,
					}))
					Expect(dataplane.addedRouteKeys.Contains("254-1-10.0.0.1/32")).To(BeFalse())
				})
				It("should add new route", func() {
					Expect(dataplane.routeKeyToRoute["254-2-10.0.0.2/32"]).To(Equal(netlink.Route{
						LinkIndex: 2,
						Dst:       &ip2,
						Type:      syscall.RTN_UNICAST,
						Protocol:  FelixRouteProtocol,
						Scope:     netlink.SCOPE_LINK,
					}))
				})
				It("should update changed route", func() {
					Expect(dataplane.routeKeyToRoute).To(HaveKey("254-3-10.0.1.3/32"))
					Expect(dataplane.routeKeyToRoute["254-3-10.0.1.3/32"]).To(Equal(netlink.Route{
						LinkIndex: 3,
						Dst:       &ip13,
						Type:      syscall.RTN_UNICAST,
						Protocol:  FelixRouteProtocol,
						Scope:     netlink.SCOPE_LINK,
					}))
					Expect(dataplane.deletedRouteKeys.Contains("254-3-10.0.0.3/32")).To(BeTrue())
				})
				It("should have expected number of routes at the end", func() {
					Expect(len(dataplane.routeKeyToRoute)).To(Equal(4),
						fmt.Sprintf("Wrong number of routes %v: %v",
							len(dataplane.routeKeyToRoute),
							dataplane.routeKeyToRoute))
				})
				if failFlags&(failNextSetSocketTimeout|
					failNextNewNetlinkHandle|
					failNextLinkByName|
					failNextLinkList|
					failNextRouteAdd|
					failNextRouteDel|
					failNextAddARP|
					failNextRouteList) != 0 {
					It("should reconnect to netlink", func() {
						Expect(dataplane.NumNewNetlinkCalls).To(Equal(2))
					})
				} else {
					It("should not reconnect to netlink", func() {
						Expect(dataplane.NumNewNetlinkCalls).To(Equal(1))
					})
				}

				Describe("after an external route addition with route removal enabled", func() {
					JustBeforeEach(func() {
						cali1Route2 = netlink.Route{
							LinkIndex: cali1.attrs.Index,
							Dst:       mustParseCIDR("10.0.0.22/32"),
							Type:      syscall.RTN_UNICAST,
							Scope:     netlink.SCOPE_LINK,
						}
						dataplane.addMockRoute(&cali1Route2)
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
					})

					It("shouldn't spot the update", func() {
						Expect(dataplane.routeKeyToRoute).To(HaveLen(5))
						Expect(dataplane.routeKeyToRoute).To(ContainElement(cali1Route2))
					})
					It("after a QueueResync() should not remove the route", func() {
						rt.QueueResync()
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
						Expect(dataplane.routeKeyToRoute).To(HaveLen(4))
						Expect(dataplane.routeKeyToRoute).NotTo(ContainElement(cali1Route2))
					})
				})

				Describe("after an external route remove with route removal disabled", func() {
					JustBeforeEach(func() {
						dataplane.removeMockRoute(&cali1Route)
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
					})

					It("shouldn't spot the update", func() {
						Expect(dataplane.routeKeyToRoute).To(HaveLen(3))
						Expect(dataplane.routeKeyToRoute).NotTo(ContainElement(cali1Route))
					})
					It("after a QueueResync() should remove the route", func() {
						rt.QueueResync()
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
						Expect(dataplane.routeKeyToRoute).To(HaveLen(4))
						Expect(dataplane.routeKeyToRoute).To(ContainElement(cali1Route))
					})
				})
			})
		}
	})

	Describe("with a down interface", func() {
		var cali1 *mockLink
		var cali1Route netlink.Route
		BeforeEach(func() {
			cali1 = dataplane.addIface(1, "cali1", false, false)
			cali1Route = netlink.Route{
				LinkIndex: cali1.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&cali1Route)
		})
		It("with no failures, it should still try to clean up the route", func() {
			err := rt.Apply()
			Expect(err).To(BeNil())
			Expect(dataplane.routeKeyToRoute).To(BeEmpty())
		})
		for _, failure := range []failFlags{
			failNextLinkByName,
			failNextRouteDel,
			failNextRouteList,
		} {
			failure := failure
			It(fmt.Sprintf("with a %v failure, it should give up", failure), func() {
				dataplane.failuresToSimulate = failure
				err := rt.Apply()
				Expect(err).To(BeNil())
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route))
			})
			It(fmt.Sprintf("with a %v failure, it shouldn't leave the interface dirty", failure), func() {
				// First Apply() with a failure.
				dataplane.failuresToSimulate = failure
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// All failures should have been hit.
				Expect(dataplane.failuresToSimulate).To(BeZero())
				// Try another Apply(), the interface shouldn't be marked dirty
				// so nothing should happen.
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route))
			})
			It(fmt.Sprintf("with a %v failure it should ignore Down updates", failure), func() {
				// First Apply() with a failure.
				dataplane.failuresToSimulate = failure
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// Fire in the update.
				rt.OnIfaceStateChanged("cali1", ifacemonitor.StateDown)
				// Try another Apply(), the interface shouldn't be marked dirty
				// so nothing should happen.
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route))
			})
			It(fmt.Sprintf("with a %v failure, then an interface kick, it should sync", failure), func() {
				dataplane.failuresToSimulate = failure
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				// Set interface up
				rt.OnIfaceStateChanged("cali1", ifacemonitor.StateUp)
				cali1 = dataplane.addIface(1, "cali1", true, true)

				// Now, the apply should work.
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.routeKeyToRoute).To(BeEmpty())
			})
		}
	})
})

var _ = Describe("RouteTable (main table)", func() {
	var dataplane *mockDataplane
	var t *mockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = &mockDataplane{
			nameToLink:       map[string]netlink.Link{},
			routeKeyToRoute:  map[string]netlink.Route{},
			addedRouteKeys:   set.New(),
			deletedRouteKeys: set.New(),
			updatedRouteKeys: set.New(),
		}
		startTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		Expect(err).NotTo(HaveOccurred())
		t = &mockTime{
			currentTime: startTime,
		}
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.setAutoIncrement(11 * time.Second)
		rt = NewWithShims(
			[]string{"cali"}, true,
			4,
			dataplane.NewNetlinkHandle,
			false,
			10*time.Second,
			dataplane.AddStaticArpEntry,
			dataplane,
			t,
			nil,
			FelixRouteProtocol,
			true,
			0,
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	Describe("with some interfaces", func() {
		var cali1, eth0 *mockLink
		var gatewayRoute, cali1Route, cali1RouteTable100 netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.addIface(0, "eth0", true, true)
			cali1 = dataplane.addIface(1, "cali1", true, true)
			cali1Route = netlink.Route{
				LinkIndex: cali1.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&cali1Route)
			cali1RouteTable100 = netlink.Route{
				LinkIndex: cali1.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     100,
			}
			dataplane.addMockRoute(&cali1RouteTable100)
			gatewayRoute = netlink.Route{
				LinkIndex: eth0.attrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
			}
			dataplane.addMockRoute(&gatewayRoute)
		})
		It("should wait for the route cleanup delay", func() {
			t.setAutoIncrement(0 * time.Second)
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route, cali1RouteTable100, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
			t.incrementTime(11 * time.Second)
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1RouteTable100, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should wait for the route cleanup delay when resyncing", func() {
			t.setAutoIncrement(0 * time.Second)
			rt.QueueResync()
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route, cali1RouteTable100, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
			t.incrementTime(11 * time.Second)
			rt.QueueResync()
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1RouteTable100, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should clean up only routes from the required table", func() {
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1RouteTable100, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
	})
})

var _ = Describe("RouteTable (table 100)", func() {
	var dataplane *mockDataplane
	var t *mockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = &mockDataplane{
			nameToLink:       map[string]netlink.Link{},
			routeKeyToRoute:  map[string]netlink.Route{},
			addedRouteKeys:   set.New(),
			deletedRouteKeys: set.New(),
			updatedRouteKeys: set.New(),
		}
		startTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		Expect(err).NotTo(HaveOccurred())
		t = &mockTime{
			currentTime: startTime,
		}
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.setAutoIncrement(11 * time.Second)
		rt = NewWithShims(
			[]string{"cali", InterfaceNone}, false, // exact interface match
			4,
			dataplane.NewNetlinkHandle,
			false,
			10*time.Second,
			dataplane.AddStaticArpEntry,
			dataplane,
			t,
			nil,
			FelixRouteProtocol,
			true,
			100,
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	Describe("with some interfaces", func() {
		var cali, eth0 *mockLink
		var gatewayRoute, caliRoute, caliRouteTable100, throwRoute netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.addIface(0, "eth0", true, true)
			cali = dataplane.addIface(1, "cali", true, true)
			caliRoute = netlink.Route{
				LinkIndex: cali.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&caliRoute)
			caliRouteTable100 = netlink.Route{
				LinkIndex: cali.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     100,
			}
			dataplane.addMockRoute(&caliRouteTable100)
			gatewayRoute = netlink.Route{
				LinkIndex: eth0.attrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
			}
			dataplane.addMockRoute(&gatewayRoute)
			throwRoute = netlink.Route{
				LinkIndex: 0,
				Dst:       mustParseCIDR("10.10.10.10/32"),
				Type:      syscall.RTN_THROW,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_NOWHERE,
				Table:     100,
			}
			dataplane.addMockRoute(&throwRoute)
		})
		It("should tidy up non-link routes immediately and wait for the route cleanup delay for interface routes", func() {
			t.setAutoIncrement(0 * time.Second)
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(caliRoute, caliRouteTable100, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
			t.incrementTime(11 * time.Second)
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should wait for the route cleanup delay when resyncing", func() {
			t.setAutoIncrement(0 * time.Second)
			rt.QueueResync()
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(caliRoute, caliRouteTable100, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
			t.incrementTime(11 * time.Second)
			rt.QueueResync()
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should clean up only routes from the required table", func() {
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})

		Describe("after configuring a throw route", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the route should remain", func() {
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, throwRoute))
				Expect(dataplane.addedRouteKeys).To(BeEmpty())
			})
		})

		Describe("after configuring a throw route and then deleting it", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteRemove(InterfaceNone, ip.MustParseCIDROrIP("10.10.10.10/32"))
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the route should be removed", func() {
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute))
				Expect(dataplane.addedRouteKeys).To(BeEmpty())
			})
		})

		Describe("after configuring a throw route and then replacing it with a blackhole route", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeBlackhole,
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the blackhole route should remain", func() {
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, netlink.Route{
					LinkIndex: 0,
					Dst:       mustParseCIDR("10.10.10.10/32"),
					Type:      syscall.RTN_BLACKHOLE,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_NOWHERE,
					Table:     100,
				}))
				Expect(dataplane.addedRouteKeys.Contains("100-0-10.10.10.10/32")).To(BeTrue())
				Expect(dataplane.deletedRouteKeys.Contains("100-0-10.10.10.10/32")).To(BeTrue())
			})
		})

		Describe("after configuring a blackhole route and then replacing it with a prohibit route", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeBlackhole,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeProhibit,
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the prohibit route should remain", func() {
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, netlink.Route{
					LinkIndex: 0,
					Dst:       mustParseCIDR("10.10.10.10/32"),
					Type:      syscall.RTN_PROHIBIT,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_NOWHERE,
					Table:     100,
				}))
				Expect(dataplane.addedRouteKeys.Contains("100-0-10.10.10.10/32")).To(BeTrue())
				Expect(dataplane.deletedRouteKeys.Contains("100-0-10.10.10.10/32")).To(BeTrue())
			})
		})
	})
})

var _ = Describe("Tests to verify netlink interface", func() {
	It("Should give expected error for missing interface", func() {
		_, err := netlink.LinkByName("dsfhjakdhfjk")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found"))
	})
})

var _ = Describe("Tests to verify ip version is policed", func() {
	It("Should panic with an invalid IP version", func() {
		Expect(func() {
			dataplane := &mockDataplane{
				nameToLink:       map[string]netlink.Link{},
				routeKeyToRoute:  map[string]netlink.Route{},
				addedRouteKeys:   set.New(),
				deletedRouteKeys: set.New(),
				updatedRouteKeys: set.New(),
			}
			startTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
			Expect(err).NotTo(HaveOccurred())
			t := &mockTime{
				currentTime: startTime,
			}
			_ = NewWithShims(
				[]string{"cali", InterfaceNone}, false,
				5, // invalid IP version
				dataplane.NewNetlinkHandle,
				false,
				10*time.Second,
				dataplane.AddStaticArpEntry,
				dataplane,
				t,
				nil,
				FelixRouteProtocol,
				true,
				100,
			)
		}).To(Panic())
	})
})

func mustParseCIDR(cidr string) *net.IPNet {
	_, c, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	return c
}

type failFlags uint32

const (
	failNextLinkList failFlags = 1 << iota
	failNextLinkByName
	failNextLinkByNameNotFound
	failNextRouteList
	failNextRouteAdd
	failNextRouteDel
	failNextAddARP
	failNextNewNetlinkHandle
	failNextSetSocketTimeout
	failNone failFlags = 0
)

var failureScenarios = []failFlags{
	failNone,
	failNextLinkList,
	failNextLinkByName,
	failNextLinkByNameNotFound,
	failNextRouteList,
	failNextRouteAdd,
	failNextRouteDel,
	failNextAddARP,
	failNextNewNetlinkHandle,
	failNextSetSocketTimeout,
}

func (f failFlags) String() string {
	parts := []string{}
	if f&failNextLinkList != 0 {
		parts = append(parts, "failNextLinkList")
	}
	if f&failNextLinkByName != 0 {
		parts = append(parts, "failNextLinkByName")
	}
	if f&failNextLinkByNameNotFound != 0 {
		parts = append(parts, "failNextLinkByNameNotFound")
	}
	if f&failNextRouteList != 0 {
		parts = append(parts, "failNextRouteList")
	}
	if f&failNextRouteAdd != 0 {
		parts = append(parts, "failNextRouteAdd")
	}
	if f&failNextRouteDel != 0 {
		parts = append(parts, "failNextRouteDel")
	}
	if f&failNextAddARP != 0 {
		parts = append(parts, "failNextAddARP")
	}
	if f&failNextNewNetlinkHandle != 0 {
		parts = append(parts, "failNextNewNetlinkHandle")
	}
	if f&failNextSetSocketTimeout != 0 {
		parts = append(parts, "failNextSetSocketTimeout")
	}
	if f == 0 {
		parts = append(parts, "failNone")
	}
	return strings.Join(parts, "|")
}

type mockDataplane struct {
	nameToLink       map[string]netlink.Link
	routeKeyToRoute  map[string]netlink.Route
	addedRouteKeys   set.Set
	deletedRouteKeys set.Set
	updatedRouteKeys set.Set

	NumNewNetlinkCalls int
	NetlinkOpen        bool

	PersistentlyFailToConnect bool

	persistFailures    bool
	failuresToSimulate failFlags

	mutex                   sync.Mutex
	deletedConntrackEntries []net.IP
	ConntrackSleep          time.Duration
}

func (d *mockDataplane) addIface(idx int, name string, up bool, running bool) *mockLink {
	flags := net.Flags(0)
	var rawFlags uint32
	if up {
		flags |= net.FlagUp
		rawFlags |= syscall.IFF_UP
	}
	if running {
		rawFlags |= syscall.IFF_RUNNING
	}
	link := &mockLink{
		attrs: netlink.LinkAttrs{
			Name:     name,
			Flags:    flags,
			RawFlags: rawFlags,
			Index:    idx,
		},
	}
	d.nameToLink[name] = link
	return link
}

func (d *mockDataplane) shouldFail(flag failFlags) bool {
	flagPresent := d.failuresToSimulate&flag != 0
	if !d.persistFailures {
		d.failuresToSimulate &^= flag
	}
	if flagPresent {
		log.WithField("flag", flag).Warn("Mock dataplane: triggering failure")
	}
	return flagPresent
}

func (d *mockDataplane) NewNetlinkHandle() (HandleIface, error) {
	d.NumNewNetlinkCalls++
	if d.PersistentlyFailToConnect || d.shouldFail(failNextNewNetlinkHandle) {
		return nil, simulatedError
	}
	Expect(d.NetlinkOpen).To(BeFalse())
	d.NetlinkOpen = true
	return d, nil
}

func (d *mockDataplane) Delete() {
	Expect(d.NetlinkOpen).To(BeTrue())
	d.NetlinkOpen = false
}

func (d *mockDataplane) SetSocketTimeout(to time.Duration) error {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextSetSocketTimeout) {
		return simulatedError
	}
	return nil
}

func (d *mockDataplane) LinkList() ([]netlink.Link, error) {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextLinkList) {
		return nil, simulatedError
	}
	var links []netlink.Link
	for _, link := range d.nameToLink {
		links = append(links, link)
	}
	return links, nil
}

func (d *mockDataplane) LinkByName(name string) (netlink.Link, error) {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextLinkByNameNotFound) {
		return nil, notFound
	}
	if d.shouldFail(failNextLinkByName) {
		return nil, simulatedError
	}
	if link, ok := d.nameToLink[name]; ok {
		return link, nil
	} else {
		return nil, notFound
	}
}

func (d *mockDataplane) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextRouteList) {
		return nil, simulatedError
	}
	var routes []netlink.Route
	for _, route := range d.routeKeyToRoute {
		if filter != nil && filterMask&netlink.RT_FILTER_OIF != 0 && route.LinkIndex != filter.LinkIndex {
			// Filtering by interface and link indices do not match.
			continue
		}
		if (filter == nil || filterMask&netlink.RT_FILTER_TABLE == 0) && route.Table != unix.RT_TABLE_MAIN && route.Table != 0 {
			// Not filtering by table and does not match main table.
			continue
		}
		if filter != nil && filterMask&netlink.RT_FILTER_TABLE != 0 && route.Table != filter.Table {
			// Filtering by table and table indices do not match.
			continue
		}
		if route.Table == 0 {
			// Mimic the kernel - the route table will be filled in.
			route.Table = unix.RT_TABLE_MAIN
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func (d *mockDataplane) addMockRoute(route *netlink.Route) {
	key := keyForRoute(route)
	r := *route
	if r.Table == unix.RT_TABLE_MAIN {
		// Store the main table with index 0 for simplicity with comparisons.
		r.Table = 0
	}
	d.routeKeyToRoute[key] = r
}

func (d *mockDataplane) removeMockRoute(route *netlink.Route) {
	key := keyForRoute(route)
	delete(d.routeKeyToRoute, key)
}

func (d *mockDataplane) RouteAdd(route *netlink.Route) error {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextRouteAdd) {
		return simulatedError
	}
	key := keyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteAdd called")
	d.addedRouteKeys.Add(key)
	if _, ok := d.routeKeyToRoute[key]; ok {
		return alreadyExists
	} else {
		r := *route
		if r.Table == unix.RT_TABLE_MAIN {
			// Store main table routes with 0 index for simplicity of comparison.
			r.Table = 0
		}
		d.routeKeyToRoute[key] = r
		return nil
	}
}

func (d *mockDataplane) RouteDel(route *netlink.Route) error {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextRouteDel) {
		return simulatedError
	}
	key := keyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteDel called")
	d.deletedRouteKeys.Add(key)
	// Route was deleted, but is planned on being readded
	if _, ok := d.routeKeyToRoute[key]; ok {
		delete(d.routeKeyToRoute, key)
		d.updatedRouteKeys.Add(key)
		return nil
	} else {
		return nil
	}
}

func (d *mockDataplane) AddStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error {
	if d.shouldFail(failNextAddARP) {
		return simulatedError
	}
	log.WithFields(log.Fields{
		"cidr":      cidr,
		"destMac":   destMAC,
		"ifaceName": ifaceName,
	}).Info("Mock dataplane: adding ARP entry")
	return nil
}

func (d *mockDataplane) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {
	log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"ipAddr":    ipAddr,
		"sleepTime": d.ConntrackSleep,
	}).Info("Mock dataplane: Removing conntrack flows")
	d.mutex.Lock()
	d.deletedConntrackEntries = append(d.deletedConntrackEntries, ipAddr)
	d.mutex.Unlock()
	time.Sleep(d.ConntrackSleep)
}

func (d *mockDataplane) GetDeletedConntrackEntries() []net.IP {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	cpy := make([]net.IP, len(d.deletedConntrackEntries))
	copy(cpy, d.deletedConntrackEntries)
	return cpy
}

func keyForRoute(route *netlink.Route) string {
	table := route.Table
	if table == 0 {
		table = unix.RT_TABLE_MAIN
	}
	key := fmt.Sprintf("%v-%v-%v", table, route.LinkIndex, route.Dst)
	log.WithField("routeKey", key).Debug("Calculated route key")
	return key
}

type mockLink struct {
	attrs netlink.LinkAttrs
}

func (l *mockLink) Attrs() *netlink.LinkAttrs {
	return &l.attrs
}

func (l *mockLink) Type() string {
	return "not-implemented"
}

type mockTime struct {
	currentTime   time.Time
	autoIncrement time.Duration
}

func (m *mockTime) Now() time.Time {
	t := m.currentTime
	m.incrementTime(m.autoIncrement)
	return t
}
func (m *mockTime) Since(t time.Time) time.Duration {
	return m.Now().Sub(t)
}

func (m *mockTime) setAutoIncrement(t time.Duration) {
	m.autoIncrement = t
}

func (m *mockTime) incrementTime(t time.Duration) {
	m.currentTime = m.currentTime.Add(t)
}
