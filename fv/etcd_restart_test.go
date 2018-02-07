// +build fvtests

// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/gomega"

	"errors"
	"fmt"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

var _ = Context("etcd restart", func() {

	var (
		etcd    *containers.Container
		felixes []*containers.Felix
		client  client.Interface
		w       [2]*workload.Workload
		hostW   [2]*workload.Workload
		cc      *workload.ConnectivityChecker
	)

	BeforeEach(func() {
		felixes, etcd, client = containers.StartNNodeEtcdTopology(2, containers.DefaultTopologyOptions())

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		defaultProfile := api.NewProfile()
		defaultProfile.Name = "default"
		defaultProfile.Spec.LabelsToApply = map[string]string{"default": ""}
		defaultProfile.Spec.Egress = []api.Rule{{Action: api.Allow}}
		defaultProfile.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		_, err := client.Profiles().Create(utils.Ctx, defaultProfile, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Wait until the tunl0 device appears; it is created when felix inserts the ipip module
		// into the kernel.
		Eventually(func() error {
			links, err := netlink.LinkList()
			if err != nil {
				return err
			}
			for _, link := range links {
				if link.Attrs().Name == "tunl0" {
					return nil
				}
			}
			return errors.New("tunl0 wasn't auto-created")
		}).Should(BeNil())

		// Create workloads, using that profile.  One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wIface := fmt.Sprintf("cali1%d", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(felixes[ii], wName, wIface, wIP, "8055", "tcp")
			w[ii].Configure(client)

			hostW[ii] = workload.Run(felixes[ii], fmt.Sprintf("host%d", ii), "", felixes[ii].IP, "8055", "tcp")
		}

		cc = &workload.ConnectivityChecker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "r")
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
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	It("should survive an ungraceful etcd termination", func() {
		By("having workload to workload connectivity", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})

		// By("killing etcd", func() {
		// Kill etcd so that it cannot gracefully terminate connections.
		//err := exec.Command("docker", "restart", "-t", "0", etcd.Name).Run()
		//Expect(err).NotTo(HaveOccurred())
		//time.Sleep(5 * time.Second)
		// })

		By("silently dropping etcd packets", func() {
			// Add an iptables rule which drops all traffic between Felix/etcd and drop the conntrack entry.
			for _, felix := range felixes {
				felix.Exec("iptables", "-t", "raw", "-A", "OUTPUT", "-d", etcd.IP, "-j", "DROP")
				felix.Exec("iptables", "-t", "raw", "-A", "PREROUTING", "-d", etcd.IP, "-j", "DROP")
				felix.Exec("iptables", "-t", "raw", "-A", "PREROUTING", "-s", etcd.IP, "-j", "DROP")
				felix.Exec("conntrack", "-D", "--dst", etcd.IP)
			}
		})

		time.Sleep(30 * time.Second)

		By("reconnecting to etcd", func() {
			// Add an iptables rule which drops all traffic between Felix/etcd.
			for _, felix := range felixes {
				felix.Exec("iptables", "-t", "raw", "-D", "OUTPUT", "-d", etcd.IP, "-j", "DROP")
				felix.Exec("iptables", "-t", "raw", "-D", "PREROUTING", "-d", etcd.IP, "-j", "DROP")
				felix.Exec("iptables", "-t", "raw", "-D", "PREROUTING", "-s", etcd.IP, "-j", "DROP")
			}
		})

		By("creating a deny-all GNP", func() {
			// Create a Policy which denies all traffic and assert it is enforced.
			// This shows that Felix has survied the etcd restart and is still receiving updates.
			deny := api.NewGlobalNetworkPolicy()
			deny.Name = "deny-all"
			deny.Spec.Selector = "all()"
			deny.Spec.Egress = []api.Rule{{Action: api.Deny}}
			deny.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, deny, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		By("no longer having workload to workload connectivity", func() {
			cc.ResetExpectations()
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[1], w[0])
			cc.CheckConnectivity()
		})
	})
})
