// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package fv

import (
	"regexp"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf attachment", []apiconfig.DatastoreType{apiconfig.EtcdV3 /*, apiconfig.Kubernetes*/}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra               infrastructure.DatastoreInfra
		felixes             []*infrastructure.Felix
		firstRun, secondRun chan struct{}
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()

		opts.ExtraEnvVars = map[string]string{
			"FELIX_BPFENABLED":              "true",
			"FELIX_DEBUGDISABLELOGDROPPING": "true",
		}
		felixes, _ = infrastructure.StartNNodeTopology(1, opts, infra)

		err := infra.AddAllowToDatastore("host-endpoint=='true'")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		for _, felix := range felixes {
			felix.Stop()
		}

		infra.Stop()
	})

	It("should not reattach bpf programs", func() {
		for _, felix := range felixes {
			firstRun = felix.WatchStdoutFor(regexp.MustCompile("Reattaching it to make sure"))
			secondRun = felix.WatchStdoutFor(regexp.MustCompile("Program already attached, skip reattaching"))
			log.Info("Felix is started")
			Eventually(firstRun, "10s", "100ms").Should(BeClosed())
			time.Sleep(3 * time.Second)
			felix.Restart()
			log.Info("Felix is restarted")
			Eventually(secondRun, "10s", "100ms").Should(BeClosed())
		}
	})
})
