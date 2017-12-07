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

	Context("with 150k workloads", func() {

		BeforeEach(func() {
			log.Info("Configuring WorkloadEndpoints...")
			for ii := 0; ii < 150000; ii++ {
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
		})

		It("should be possible to upgrade that data", func() {
			time.Sleep(10 * time.Minute)
		})
	})
})
