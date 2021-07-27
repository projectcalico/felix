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

package winfv_test

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

func powershell(args ...string) (string, string, error) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", "", err
	}

	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(ps, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return "", "", err
	}

	return stdout.String(), stderr.String(), err
}

func getPodIP(name, namespace string) string {
	cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config get pod %s -n %s -o jsonpath='{.status.podIP}'`,
		name, namespace)
	ip, _, err := powershell(cmd)
	if err != nil {
		Fail(fmt.Sprintf("could not get pod IP for %v/%v: %v", namespace, name, err))
	}
	return ip
}

var _ = Describe("Windows policy test", func() {
	var (
		porter, client, clientB, nginx string
	)

	BeforeEach(func() {
		// Get Pod IPs.
		client = getPodIP("client", "demo")
		clientB = getPodIP("client-b", "demo")
		porter = getPodIP("porter", "demo")
		nginx = getPodIP("nginx", "demo")
		log.Infof("Pod IP client %s, client-b %s, porter %s, nginx %s",
			client, clientB, porter, nginx)

		Expect(client).NotTo(BeEmpty())
		Expect(clientB).NotTo(BeEmpty())
		Expect(porter).NotTo(BeEmpty())
		Expect(nginx).NotTo(BeEmpty())
	})

	Context("ingress policy tests", func() {
		It("client pod can connect to porter pod", func() {
			cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config exec -t client -n demo -- wget %v -T 5 -O -`, porter)
			output, _, err := powershell(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Contains(output, "200")).To(BeTrue())
		})
		It("client-b pod can't connect to porter pod", func() {
			cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config exec -t client-b -n demo -- wget %v -T 5 -O -`, porter)
			_, _, err := powershell(cmd)
			Expect(err).To(HaveOccurred())
		})
	})
})
