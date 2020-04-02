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

// +build fvtests

package fv_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/connectivity"
	"github.com/projectcalico/felix/fv/utils"

	"fmt"

	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("all-interfaces host endpoints", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  client.Interface
		w       [2]*workload.Workload
		hostW   [2]*workload.Workload
		cc      *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		options := infrastructure.DefaultTopologyOptions()
		options.IPIPEnabled = false
		felixes, client = infrastructure.StartNNodeTopology(2, options, infra)

		// Create workloads, using that profile. One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", "tcp")
			w[ii].ConfigureInDatastore(infra)

			hostW[ii] = workload.Run(felixes[ii], fmt.Sprintf("host%d", ii), "", felixes[ii].IP, "8055", "tcp")
		}

		cc = &connectivity.Checker{}
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
		for _, wl := range hostW {
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

	Context("with all-interfaces host protection policy in place", func() {
		BeforeEach(func() {
			// Install a default profile that allows all ingress and egress, in the absence of any policy.
			infra.AddDefaultAllow()

			for _, f := range felixes {
				hep := api.NewHostEndpoint()
				hep.Name = "all-interfaces-" + f.Name
				hep.Labels = map[string]string{
					"host-endpoint": "true",
					"hostname":      f.Hostname,
				}
				hep.Spec.Node = f.Hostname
				hep.Spec.ExpectedIPs = []string{f.IP}
				hep.Spec.InterfaceName = "*"
				_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should have workload to workload connectivity", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})

		It("should have host to workload connectivity", func() {
			cc.ExpectSome(felixes[0], w[1])
			cc.ExpectSome(felixes[0], w[0])
			cc.CheckConnectivity()
		})

		It("should have host to host connectivity", func() {
			cc.ExpectSome(felixes[0], hostW[1])
			cc.ExpectSome(felixes[1], hostW[0])
			cc.CheckConnectivity()
		})

		Context("With a deny all policy that selects all hosts", func() {
			var res *api.GlobalNetworkPolicy
			var err error

			BeforeEach(func() {
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "deny-all"
				policy.Spec.Selector = "has(host-endpoint)"
				policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				policy.Spec.Egress = []api.Rule{{Action: api.Deny}}
				res, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should still have workload to workload connectivity", func() {
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[1], w[0])
				cc.CheckConnectivity()
			})

			It("should not have host to other workload connectivity", func() {
				cc.ExpectNone(felixes[0], w[1])
				cc.CheckConnectivity()
			})

			It("should not have host to host connectivity", func() {
				cc.ExpectNone(felixes[0], hostW[1])
				cc.ExpectNone(felixes[1], hostW[0])
				cc.CheckConnectivity()
			})

			It("should always have host to own workload connectivity despite of any normal deny policy rules", func() {
				cc.ExpectSome(felixes[0], w[0])
				cc.ExpectSome(felixes[1], w[1])
				cc.CheckConnectivity()
			})

			Context("with apply-on-forward set on the existing deny-all policy", func() {
				BeforeEach(func() {
					res.Spec.ApplyOnForward = true
					_, err := client.GlobalNetworkPolicies().Update(utils.Ctx, res, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})
				It("should no longer have workload to workload connectivity", func() {
					cc.ExpectNone(w[0], w[1])
					cc.ExpectNone(w[1], w[0])
					cc.CheckConnectivity()
				})

				It("should stll not have host to other workload connectivity", func() {
					cc.ExpectNone(felixes[0], w[1])
					cc.CheckConnectivity()
				})

				It("should still not have host to host connectivity", func() {
					cc.ExpectNone(felixes[0], hostW[1])
					cc.ExpectNone(felixes[1], hostW[0])
					cc.CheckConnectivity()
				})

				It("should still have host to own workload connectivity despite any normal deny policy rules", func() {
					cc.ExpectSome(felixes[0], w[0])
					cc.ExpectSome(felixes[1], w[1])
					cc.CheckConnectivity()
				})
			})
		})

		Context("With a deny all ingress policy on felix-1 host", func() {
			BeforeEach(func() {
				// Create a policy selecting felix[1] that denies ingress.
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "felix-1"
				policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[1].Hostname)
				policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should still have workload to workload connectivity", func() {
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[1], w[0])
				cc.CheckConnectivity()
			})

			It("should still allow traffic to its (felix-1's) workloads", func() {
				cc.ExpectSome(felixes[0], w[1])
				cc.CheckConnectivity()
			})

			It("should not allow other hosts or other workloads to reach it", func() {
				cc.ExpectNone(felixes[0], hostW[1])
				cc.ExpectNone(w[0], hostW[1])
				cc.CheckConnectivity()
			})

			It("should still be able to reach felix-0", func() {
				// felix-1 is still allowed egress.
				cc.ExpectSome(felixes[1], hostW[0])
				cc.ExpectSome(felixes[1], w[0])
				cc.CheckConnectivity()
			})
		})

		Context("With an apply-on-forward policy on felix-0 blocking egress to felix-1", func() {
			var err error

			BeforeEach(func() {
				// Create an AOF policy selecting felix[0] denying egress to
				// felix[1].
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "felix-0"
				policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[0].Hostname)
				policy.Spec.ApplyOnForward = true
				policy.Spec.Egress = []api.Rule{
					{
						Action: api.Deny,
						Destination: api.EntityRule{
							Selector: fmt.Sprintf("hostname == '%s'", felixes[1].Hostname),
						},
					},
				}
				_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should not have workload to workload connectivity", func() {
				cc.ExpectNone(w[0], w[1])
				cc.CheckConnectivity()
			})

			It("will deny(?) felix-1 from reaching felix-0", func() {
				// TODO
				cc.ExpectNone(w[1], w[0])
				cc.ExpectNone(felixes[1], w[0])
				cc.CheckConnectivity()
			})

			It("should deny felix-0 from reaching felix-1", func() {
				cc.ExpectNone(felixes[0], hostW[1])
				cc.ExpectNone(felixes[0], w[1])
				// But felix-1 can reach felix-0
				cc.ExpectSome(felixes[1], hostW[0])
				cc.CheckConnectivity()
			})
		})
	})
})
