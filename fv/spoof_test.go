// +build fvtests

// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package fv_test

import (
	. "github.com/onsi/ginkgo"

	"fmt"

	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("spoof tests", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		w       [3]*workload.Workload
		cc      *workload.ConnectivityChecker
	)

	/*
		Context("using IPv4", func() {
			BeforeEach(func() {
				infra = getInfra()

				// Setup 3 felixes. felixes[0] will spoof felixes[2] and try to reach
				// felixes[1].
				felixes, _ = infrastructure.StartNNodeTopology(3, infrastructure.DefaultTopologyOptions(), infra)

				// Install a default profile that allows all ingress and egress, in the absence of any Policy.
				infra.AddDefaultAllow()
			})

			AfterEach(func() {
				if CurrentGinkgoTestDescription().Failed {
					for _, felix := range felixes {
						felix.Exec("iptables-save", "-c")
						felix.Exec("ipset", "list")
						felix.Exec("ip", "r")
						felix.Exec("ip", "a")
					}
				}

				for _, wl := range w {
					wl.Stop()
				}
				for _, felix := range felixes {
					felix.Stop()
				}

				if CurrentGinkgoTestDescription().Failed {
					infra.DumpErrorData()
				}
				infra.Stop()
			})

			setupWorkloadsAndConnectivityChecker := func(protocol string) {
				for ii := range w {
					wIP := fmt.Sprintf("10.65.%d.2", ii)
					wName := fmt.Sprintf("w%d", ii)
					w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", protocol)
					w[ii].ConfigureInDatastore(infra)
				}

				cc = &workload.ConnectivityChecker{Protocol: protocol}
			}

			It("should drop udp traffic that has had its IP spoofed", func() {
				setupWorkloadsAndConnectivityChecker("udp")
				// Setup a spoofed workload. w[0] has the IP 10.65.0.2.
				// Make it use 10.65.2.2 to test connections instead.
				spoofed := &workload.SpoofedWorkload{
					Workload:        w[0],
					SpoofedSourceIP: "10.65.2.2",
				}
				cc.ExpectNone(spoofed, w[1])
				cc.ExpectSome(w[1], w[0])
				cc.CheckConnectivity()
			})

			It("should drop tcp traffic that has had its IP spoofed", func() {
				setupWorkloadsAndConnectivityChecker("tcp")
				// Setup a spoofed workload. w[0] has the IP 10.65.0.2.
				// Make it use 10.65.2.2 to test connections instead.
				spoofed := &workload.SpoofedWorkload{
					Workload:        w[0],
					SpoofedSourceIP: "10.65.2.2",
				}
				cc.ExpectNone(spoofed, w[1])
				cc.ExpectSome(w[1], w[0])
				cc.CheckConnectivity()
			})
		})
	*/

	Context("using IPv6", func() {
		BeforeEach(func() {
			infra = getInfra()

			// Setup 3 felixes. felixes[0] will spoof felixes[2] and try to reach
			// felixes[1].
			opts := infrastructure.DefaultTopologyOptions()
			opts.EnableIPv6 = true
			felixes, _ = infrastructure.StartNNodeTopology(3, opts, infra)

			// Install a default profile that allows all ingress and egress, in the absence of any Policy.
			infra.AddDefaultAllow()
		})

		AfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				for _, felix := range felixes {
					felix.Exec("iptables-save", "-c")
					felix.Exec("ip6tables-save", "-c")
					felix.Exec("ipset", "list")
					felix.Exec("ip", "r")
					felix.Exec("ip", "a")
				}
			}

			for _, wl := range w {
				wl.Stop()
			}
			for _, felix := range felixes {
				felix.Stop()
			}

			if CurrentGinkgoTestDescription().Failed {
				infra.DumpErrorData()
			}
			infra.Stop()
		})

		setupWorkloadsAndConnectivityChecker := func(protocol string) {
			// Setup an offset so that we assign IPv6 addrs like so:
			// 0:0:0:0:0:ffff:a41:2
			// 0:0:0:0:0:ffff:a41:102
			// 0:0:0:0:0:ffff:a41:202
			// ...
			offset := 2
			for ii := range w {
				wIP := fmt.Sprintf("0:0:0:0:0:ffff:a41:%d", offset)
				wName := fmt.Sprintf("w%d", ii)
				w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", protocol)
				w[ii].ConfigureInDatastore(infra)
				offset += 100
			}

			cc = &workload.ConnectivityChecker{Protocol: protocol}
		}

		/*
			It("should drop udp traffic that has had its IP spoofed", func() {
				setupWorkloadsAndConnectivityChecker("udp")
				// Setup a spoofed workload. w[0] has the IP 0:0:0:0:0:ffff:a41:2.
				// Make it use 0:0:0:0:0:ffff:a41:202 to test connections instead.
				spoofed := &workload.SpoofedWorkload{
					Workload:        w[0],
					SpoofedSourceIP: "0:0:0:0:0:ffff:a41:202",
				}
				cc.ExpectNone(spoofed, w[1])
				cc.ExpectSome(w[1], w[0])
				cc.CheckConnectivity()
			})
		*/

		It("should drop tcp traffic that has had its IP spoofed", func() {
			setupWorkloadsAndConnectivityChecker("tcp")
			// Setup a spoofed workload. w[0] has the IP 0:0:0:0:0:ffff:a41:2.
			// Make it use 0:0:0:0:0:ffff:a41:202 to test connections instead.
			//spoofed := &workload.SpoofedWorkload{
			//	Workload:        w[0],
			//	SpoofedSourceIP: "0:0:0:0:0:ffff:a41:202",
			//}
			//cc.ExpectNone(spoofed, w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})
	})

})
