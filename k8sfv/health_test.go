// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package main

import (
	"net/http"
	"os/exec"
	"time"

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/health"
	"k8s.io/client-go/kubernetes"
)

var _ = Describe("health", func() {

	var (
		clientset *kubernetes.Clientset
	)

	BeforeEach(func() {
		log.Info(">>> BeforeEach <<<")
		clientset = initialize(k8sServerEndpoint)
	})

	It("Felix should be not ready", func() {
		// Because there is no config for the local node.
		triggerFelixRestart()
		for i := 0; i < 8; i++ {
			Expect(getFelixStatus("readiness")()).To(BeNumerically("==", health.StatusBad))
			time.Sleep(500 * time.Millisecond)
		}
	})

	It("Felix should be not live", func() {
		// Because there is no config for the local node.
		triggerFelixRestart()
		for i := 0; i < 8; i++ {
			Expect(getFelixStatus("liveness")()).To(BeNumerically("==", health.StatusBad))
			time.Sleep(500 * time.Millisecond)
		}
	})

	It("Typha should be ready", func() {
		Eventually(getTyphaStatus("readiness"), "8s", "0.5s").Should(BeNumerically("==", health.StatusGood))
	})

	It("Typha should be live", func() {
		Eventually(getTyphaStatus("liveness"), "8s", "0.5s").Should(BeNumerically("==", health.StatusGood))
	})

	Context("with a local host", func() {
		BeforeEach(func() {
			triggerFelixRestart()
			_ = NewDeployment(clientset, 0, true)
		})

		It("Felix should be ready", func() {
			Eventually(getFelixStatus("readiness"), "8s", "0.5s").Should(BeNumerically("==", health.StatusGood))
		})

		It("Felix should be live", func() {
			Eventually(getFelixStatus("liveness"), "8s", "0.5s").Should(BeNumerically("==", health.StatusGood))
		})

		It("Typha should be ready", func() {
			Eventually(getTyphaStatus("readiness"), "8s", "0.5s").Should(BeNumerically("==", health.StatusGood))
		})

		It("Typha should be live", func() {
			Eventually(getTyphaStatus("liveness"), "8s", "0.5s").Should(BeNumerically("==", health.StatusGood))
		})
	})

	AfterEach(func() {
		log.Info(">>> AfterEach <<<")
	})
})

func getHealthStatus(ip, port, endpoint string) func() int {
	return func() int {
		resp, err := http.Get("http://" + ip + ":" + port + "/" + endpoint)
		if err != nil {
			log.WithError(err).Error("HTTP GET failed")
			return health.StatusBad
		}
		log.WithField("resp", resp).Info("Health response")
		defer resp.Body.Close()
		return resp.StatusCode
	}
}

func getFelixStatus(endpoint string) func() int {
	return getHealthStatus(felixIP, "9099", endpoint)
}

func getTyphaStatus(endpoint string) func() int {
	return getHealthStatus(typhaIP, "9098", endpoint)
}

func triggerFelixRestart() {
	exec.Command("pkill", "-TERM", "calico-felix").Run()
	time.Sleep(1 * time.Second)
}
