// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/arp"
	"github.com/projectcalico/felix/bpf/mock"
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/proto"
)

var _ = Describe("Neigh manager", func() {
	var neighMap bpf.Map
	var mgr *bpfNeighManager
	BeforeEach(func() {
		neighMap = mock.NewMockMap(arp.MapParams)
		mgr = newBPFNeighManager(neighMap)
	})

	eth0IfIndex := 3
	eth0MAC := net.HardwareAddr([]byte{1, 2, 3, 4, 5, 6})

	neighMAC := net.HardwareAddr([]byte{5, 4, 5, 4, 5, 4})
	neighIP := net.IPv4(10, 0, 0, 1)

	It("should pass a basic test when all updates are available on time", func() {
		mgr.OnUpdate(&ifaceUpdate{
			Name:         "eth0",
			State:        ifacemonitor.StateUp,
			Index:        eth0IfIndex,
			HardwareAddr: eth0MAC,
		})

		mgr.OnUpdate(&proto.RouteUpdate{
			Type: proto.RouteType_REMOTE_HOST,
			Dst:  neighIP.String() + "/32",
		})

		mgr.OnUpdate(&neighUpdate{
			Exists:  true,
			IfIndex: eth0IfIndex,
			IP:      neighIP,
			HWAddr:  neighMAC,
		})

		k := arp.NewKey(neighIP, uint32(eth0IfIndex))

		_, err := neighMap.Get(k[:])
		Expect(err).To(HaveOccurred())

		err = mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		v, err := neighMap.Get(k[:])
		Expect(err).NotTo(HaveOccurred())

		var val arp.Value
		copy(val[:], v)
		Expect(val.SrcMAC()).To(Equal(eth0MAC))
		Expect(val.DstMAC()).To(Equal(neighMAC))
	})

	It("should not include an update until it knows it is a node", func() {
		mgr.OnUpdate(&ifaceUpdate{
			Name:         "eth0",
			State:        ifacemonitor.StateUp,
			Index:        eth0IfIndex,
			HardwareAddr: eth0MAC,
		})

		mgr.OnUpdate(&neighUpdate{
			Exists:  true,
			IfIndex: eth0IfIndex,
			IP:      neighIP,
			HWAddr:  neighMAC,
		})

		k := arp.NewKey(neighIP, uint32(eth0IfIndex))

		err := mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		_, err = neighMap.Get(k[:])
		Expect(err).To(HaveOccurred())

		err = mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// The neighbour remains unresolved because we cannot tell if it is a remote node yet.
		Expect(mgr.unresolved[eth0IfIndex]).To(HaveLen(1))

		mgr.OnUpdate(&proto.RouteUpdate{
			Type: proto.RouteType_REMOTE_HOST,
			Dst:  neighIP.String() + "/32",
		})

		_, err = neighMap.Get(k[:])
		Expect(err).NotTo(HaveOccurred())

		Expect(mgr.unresolved[eth0IfIndex]).To(HaveLen(0))
	})

	It("should not include an update until it knows the device", func() {
		mgr.OnUpdate(&proto.RouteUpdate{
			Type: proto.RouteType_REMOTE_HOST,
			Dst:  neighIP.String() + "/32",
		})

		mgr.OnUpdate(&neighUpdate{
			Exists:  true,
			IfIndex: eth0IfIndex,
			IP:      neighIP,
			HWAddr:  neighMAC,
		})

		k := arp.NewKey(neighIP, uint32(eth0IfIndex))

		err := mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		_, err = neighMap.Get(k[:])
		Expect(err).To(HaveOccurred())

		err = mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// The neighbour remains unresolved because we do not know the device yet.
		Expect(mgr.unresolved[eth0IfIndex]).To(HaveLen(1))

		mgr.OnUpdate(&ifaceUpdate{
			Name:         "eth0",
			State:        ifacemonitor.StateUp,
			Index:        eth0IfIndex,
			HardwareAddr: eth0MAC,
		})

		err = mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		_, err = neighMap.Get(k[:])
		Expect(err).NotTo(HaveOccurred())

		Expect(mgr.unresolved[eth0IfIndex]).To(HaveLen(0))
	})

	It("should remove unresolved when device removed", func() {
		mgr.OnUpdate(&neighUpdate{
			Exists:  true,
			IfIndex: eth0IfIndex,
			IP:      neighIP,
			HWAddr:  neighMAC,
		})

		err := mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// The neighbour remains unresolved because we dont know the device.
		Expect(mgr.unresolved[eth0IfIndex]).To(HaveLen(1))

		mgr.OnUpdate(&ifaceUpdate{
			Name:         "eth0",
			State:        ifacemonitor.StateDown,
			Index:        eth0IfIndex,
			HardwareAddr: eth0MAC,
		})

		err = mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(mgr.unresolved[eth0IfIndex]).To(HaveLen(0))
	})

	It("should remove unresolved when the neighbour is removed", func() {
		mgr.OnUpdate(&neighUpdate{
			Exists:  true,
			IfIndex: eth0IfIndex,
			IP:      neighIP,
			HWAddr:  neighMAC,
		})

		err := mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// The neighbour remains unresolved because we dont know the device.
		Expect(mgr.unresolved[eth0IfIndex]).To(HaveLen(1))

		mgr.OnUpdate(&neighUpdate{
			Exists:  false,
			IfIndex: eth0IfIndex,
			IP:      neighIP,
		})

		err = mgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(mgr.unresolved[eth0IfIndex]).To(HaveLen(0))
	})
})
