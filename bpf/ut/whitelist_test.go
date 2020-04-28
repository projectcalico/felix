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

package ut_test

import (
	"testing"

	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/conntrack"
	"github.com/projectcalico/felix/bpf/routes"
)

// These tests make sure that the connections are whilisted only in the direction the
// policy allowed it to open. The opposite direction is whitelisted by default as we allow
// tracked connections that satisfy policy in one direction to return.

func TestWhitelistFromWorkloadExitHost(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "WHwl"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	mc := &bpf.MapContext{}

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	hostIP = node1ip

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	defer func() {
		err := rtMap.Delete(rtKey)
		Expect(err).NotTo(HaveOccurred())
	}()
	Expect(err).NotTo(HaveOccurred())

	ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
		ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

	// Leaving workload
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Whitelisted in one direction
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).NotTo(BeTrue())
	})

	// Leaving node 1
	skbMark = 0xca100000 // CALI_SKB_MARK_SEEN

	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Still whitelisted only in one direction
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).NotTo(BeTrue())
	})

	skbMark = 0
	respPkt := udpResposeRaw(pktBytes)

	runBpfTest(t, "calico_from_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Still whitelisted only in one direction
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).NotTo(BeTrue())
	})

	skbMark = 0xca100000 // CALI_SKB_MARK_SEEN
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Still whitelisted only in one direction
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).NotTo(BeTrue())
	})
}

func TestWhitelistEnterHostToWorkload(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWwl"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	mc := &bpf.MapContext{}

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	hostIP = node1ip

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	defer func() {
		err := rtMap.Delete(rtKey)
		Expect(err).NotTo(HaveOccurred())
	}()
	Expect(err).NotTo(HaveOccurred())

	ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
		ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

	runBpfTest(t, "calico_from_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Not whitelised yet, not WEP policy applied yet.
		Expect(ctr.Data().A2B.Whitelisted).NotTo(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).NotTo(BeTrue())
	})

	skbMark = 0xca100000 // CALI_SKB_MARK_SEEN

	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Still whitelisted only in one direction
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
		Expect(ctr.Data().A2B.Whitelisted).NotTo(BeTrue())
	})

	skbMark = 0
	respPkt := udpResposeRaw(pktBytes)

	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Still whitelisted only in one direction
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
		Expect(ctr.Data().A2B.Whitelisted).NotTo(BeTrue())
	})

	skbMark = 0xca100000 // CALI_SKB_MARK_SEEN
	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Still whitelisted only in one direction
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
		Expect(ctr.Data().A2B.Whitelisted).NotTo(BeTrue())
	})
}

func TestWhitelistWorkloadToWorkload(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "WWwl"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	mc := &bpf.MapContext{}

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	hostIP = node1ip

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	defer func() {
		err := rtMap.Delete(rtKey)
		Expect(err).NotTo(HaveOccurred())
	}()
	Expect(err).NotTo(HaveOccurred())

	ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
		ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Still whitelisted only in one direction
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).NotTo(BeTrue())
	})

	skbMark = 0xca100000 // CALI_SKB_MARK_SEEN

	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		// Now whitelisted in both directions
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
	})

	respPkt := udpResposeRaw(pktBytes)

	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
	})

	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).Should(HaveKey(ctKey))

		ctr := ct[ctKey]

		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
	})
}
