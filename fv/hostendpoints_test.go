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

	Context("with all-interfaces host endpoints", func() {
		BeforeEach(func() {
			// Make sure our new host endpoints don't cut felix off from the datastore.
			err := infra.AddAllowToDatastore("host-endpoint=='true'")
			Expect(err).NotTo(HaveOccurred())

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

		It("should block host-to-host traffic in the absence of policy allowing it", func() {
			cc.ExpectNone(felixes[0], hostW[1])
			cc.ExpectNone(felixes[1], hostW[0])
			cc.CheckConnectivity()
		})

		It("should allow pod-to-pod traffic because of the allow-all default profile", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})

		It("should allow host-to-own-pod traffic policy allowing it but not host to other-pods", func() {
			cc.ExpectSome(felixes[0], w[0])
			cc.ExpectSome(felixes[1], w[1])
			cc.ExpectNone(felixes[0], w[1])
			cc.ExpectNone(felixes[1], w[0])
			cc.CheckConnectivity()
		})

		It("should allow felixes[0] to reach felixes[1] if ingress and egress policies are in place", func() {
			// Create a policy selecting felix[1] that allows egress.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "f0-egress"
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[0].Hostname)
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// But there is no policy allowing ingress into felix[1].
			cc.ExpectNone(felixes[0], hostW[1])
			cc.ExpectNone(felixes[1], hostW[0])

			// Workload connectivity is unchanged.
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()

			cc.ResetExpectations()

			// Now add a policy selecting felix[1] that allows ingress.
			policy = api.NewGlobalNetworkPolicy()
			policy.Name = "f1-ingress"
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[1].Hostname)
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Now felixes[0] can reach felixes[1].
			cc.ExpectSome(felixes[0], hostW[1])
			cc.ExpectNone(felixes[1], hostW[0])

			// Workload connectivity is unchanged.
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})
	})

	Context("with all-interfaces host endpoints, with an allow-all profile attached, and no policies", func() {
		BeforeEach(func() {
			// Install a default profile that allows all ingress and egress, in the absence of any policy.
			infra.AddDefaultAllow()

			// Determine the allow-all profile name for the host endpoints.
			defaultProfileName := "default"
			if infrastructure.K8sInfra != nil {
				defaultProfileName = "kns.default"
			}

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
				hep.Spec.Profiles = []string{defaultProfileName}
				_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should allow host-to-host traffic", func() {
			cc.ExpectSome(felixes[0], hostW[1])
			cc.ExpectSome(felixes[1], hostW[0])
			cc.CheckConnectivity()
		})

		It("should allow pod-to-pod traffic", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})

		It("should allow host-to-pod and pod-to-host traffic", func() {
			cc.ExpectSome(felixes[0], w[0])
			cc.ExpectSome(felixes[1], w[1])
			cc.ExpectSome(felixes[0], w[1])
			cc.ExpectSome(felixes[1], w[0])
			cc.ExpectSome(w[0], hostW[1])
			cc.ExpectSome(w[1], hostW[0])
			cc.CheckConnectivity()
		})

		Context("with a policy allowing access to the datastore", func() {
			BeforeEach(func() {
				// Make sure our new host endpoints don't cut felix off from the datastore.
				err := infra.AddAllowToDatastore("host-endpoint=='true'")
				Expect(err).NotTo(HaveOccurred())
			})

			It("should block host-to-host traffic if deny egress policy is in place", func() {
				// Create a policy selecting felix[1] that denies egress.
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "f0-egress"
				policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[0].Hostname)
				policy.Spec.Egress = []api.Rule{{Action: api.Deny}}
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				cc.ExpectNone(felixes[0], hostW[1])
				cc.ExpectNone(felixes[1], hostW[0])

				// Workload connectivity is unchanged.
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[1], w[0])
				cc.CheckConnectivity()
			})

			It("should block host-to-host traffic if deny ingress policy is in place", func() {
				// Now add a policy selecting felix[1] that denies ingress.
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "f1-ingress"
				policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[1].Hostname)
				policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				cc.ExpectNone(felixes[0], hostW[1])
				cc.ExpectNone(felixes[1], hostW[0])

				// Workload connectivity is unchanged.
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[1], w[0])
				cc.CheckConnectivity()
			})
		})
	})
})
