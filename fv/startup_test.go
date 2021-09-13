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

var _ = infrastructure.DatastoreDescribe("Felix startup speed", []apiconfig.DatastoreType{apiconfig.EtcdV3 /*, apiconfig.Kubernetes*/}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()

		opts.ExtraEnvVars = map[string]string{
			"FELIX_BPFENABLED":              "true",
			"FELIX_DEBUGDISABLELOGDROPPING": "true",
		}
		felixes, _ = infrastructure.StartNNodeTopology(3, opts, infra)

		err := infra.AddAllowToDatastore("host-endpoint=='true'")
		Expect(err).NotTo(HaveOccurred())

	})

	It("should not re-attach bpf programs", func() {
		for _, felix := range felixes {
			log.Info("Felix is about to start")
			felix.Start()
			<-felix.WatchStdoutFor(regexp.MustCompile("Felix starting up"))
			log.Info("Felix is started")
			felix.Restart()
			<-felix.WatchStdoutFor(regexp.MustCompile("Felix starting up"))
			log.Info("Felix is restarted")
			time.Sleep(60 * time.Minute)
		}
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
})
