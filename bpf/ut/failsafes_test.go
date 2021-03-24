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
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/bpf/failsafes"
	"github.com/projectcalico/felix/bpf/polprog"
	"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
)

func TestFailsafes(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	iphdr := *ipv4Default

	_, _, _, _, pktBytes, err := testPacket(nil, &iphdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	hostIP = dstIP // set host IP to the default dest
	hostCIDR := ip.CIDRFromNetIP(hostIP).(ip.V4CIDR)

	// Setup routing so that failsafe check knows it is localhost
	rtKey := routes.NewKey(hostCIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalHost, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	fsafeMap.Update(
		failsafes.MakeKey(17 /* UDP */, 5678 /* default dst port */, false /* inbound */).ToSlice(),
		failsafes.Value(),
	)

	denyAllRules := polprog.Rules{
		ForHostInterface: true,
		HostNormalTiers: []polprog.Tier{{
			Policies: []polprog.Policy{{
				Name: "deny all",
				Rules: []polprog.Rule{{Rule: &proto.Rule{
					Action: "Deny",
				}}},
			}},
		}},
	}

	runBpfTest(t, "calico_from_host_ep", &denyAllRules, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")
	})
}
