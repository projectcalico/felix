// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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
	"fmt"
	"testing"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/failsafes"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
)

func MapForTest(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/cali_jump_xdp",
		Type:       "prog_array",
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 8,
		Name:       "cali_jump",
	})
}

func TestXDPNoFailsafe(t *testing.T) {
	RegisterTestingT(t)

	resetBPFMaps()
	iphdr := *ipv4Default
	iphdr.TOS = 0
	_, _, _, _, pktBytes, err := testPacket(nil, &iphdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	runBpfTest(t, "calico_entrypoint_xdp", true, nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStrXDP()).To(Equal("XDP_PASS"), "expected program to return  XDP_PASS")

		Expect(res.dataOut).To(HaveLen(len(pktBytes)))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(pktBytes))
		Expect(res.dataOut[15]).To(Equal(uint8(0)))
	})
}

func TestXDPFailSafe(t *testing.T) {
	RegisterTestingT(t)

	iphdr := *ipv4Default
	iphdr.TOS = 0
	_, _, _, _, pktBytes, err := testPacket(nil, &iphdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	defer resetBPFMaps()
	err = fsafeMap.Update(
		failsafes.MakeKey(17, 5678, false, srcIP.String(), 16).ToSlice(),
		failsafes.Value(),
	)

	runBpfTest(t, "calico_entrypoint_xdp", true, nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStrXDP()).To(Equal("XDP_PASS"), "expected program to return  XDP_PASS")
		Expect(res.dataOut).To(HaveLen(len(pktBytes)))
		Expect(res.dataOut[15]).To(Equal(uint8(128)))
	})
}
