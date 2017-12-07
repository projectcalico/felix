// +build fvtests

// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/net"
)

var _ = Context("with initialized etcd datastore", func() {

	var (
		etcd   *containers.Container
		client *client.Client
	)

	BeforeEach(func() {

		etcd = containers.RunEtcd()

		client = utils.GetEtcdClient(etcd.IP)
		Eventually(client.EnsureInitialized, "10s", "1s").ShouldNot(HaveOccurred())
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	const NUM_WORKLOADS = 15000

	Context(fmt.Sprintf("with %d workloads", NUM_WORKLOADS), func() {

		BeforeEach(func() {
			log.Infof("Configuring %d WorkloadEndpoints...", NUM_WORKLOADS)
			for ii := 0; ii < NUM_WORKLOADS; ii++ {
				iiStr := fmt.Sprintf("%06d", ii)
				hostNum := ii % 247
				hostStr := fmt.Sprintf("%04d", hostNum)
				wep := api.NewWorkloadEndpoint()
				wep.Metadata.Name = "w" + iiStr
				wep.Metadata.Workload = "wl" + iiStr
				wep.Metadata.Orchestrator = "felixfv"
				wep.Metadata.Node = "host" + hostStr
				wep.Metadata.Labels = map[string]string{"name": wep.Metadata.Name}
				wep.Spec.IPNetworks = []net.IPNet{net.MustParseNetwork(fmt.Sprintf(
					"10.%d.%d.%d/32",
					ii/65536,
					(ii/256)%256,
					ii%256,
				))}
				wep.Spec.InterfaceName = "cali" + iiStr
				wep.Spec.Profiles = []string{"default"}
				_, err := client.WorkloadEndpoints().Apply(wep)
				Expect(err).NotTo(HaveOccurred())
				if (ii+1)%10000 == 0 {
					log.Infof("Configured %d WorkloadEndpoints", ii+1)
				}
			}
			log.Info("Finished configuring WorkloadEndpoints")
		})

		const CALICO_UPGRADE = "/home/neil/Downloads/calico-upgrade"

		It("should be possible to upgrade that data", func() {
			// Test and time upgrade validation.
			validateStart := time.Now()
			utils.Run("/bin/sh", "-c", fmt.Sprintf(
				"APIV1_ETCD_ENDPOINTS=http://%s:2379 ETCD_ENDPOINTS=http://%s:2379 %s validate",
				etcd.IP,
				etcd.IP,
				CALICO_UPGRADE,
			))
			validateTime := time.Since(validateStart)
			log.Infof("Took %s to validate upgrade of %d WorkloadEndpoints", validateTime, NUM_WORKLOADS)

			// Test and time actual upgrade.
			convertStart := time.Now()
			utils.Run("/bin/sh", "-c", fmt.Sprintf(
				"echo yes | APIV1_ETCD_ENDPOINTS=http://%s:2379 ETCD_ENDPOINTS=http://%s:2379 %s start",
				etcd.IP,
				etcd.IP,
				CALICO_UPGRADE,
			))
			convertTime := time.Since(convertStart)
			log.Infof("Took %s to upgrade %d WorkloadEndpoints", convertTime, NUM_WORKLOADS)
		})
	})
})
