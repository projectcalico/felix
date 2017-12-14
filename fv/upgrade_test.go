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
	"os"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/scope"
)

// The measurements that /usr/bin/time can report and that are of interest to us, for a single
// calico-upgrade invocation.
type measurements struct {
	sharedTextSizeK     int     // %X
	unsharedDataSizeK   int     // %D
	maxResidentSetSizeK int     // %M
	majorPageFaults     int     // %F (basically indicates swapping)
	kernelCPUSecs       float64 // %S
	userCPUSecs         float64 // %U
}

const MEASURE_FORMAT = "'%X %D %M %F %S %U'"

func readMeasurements(fileName string) *measurements {
	m := &measurements{}
	f, err := os.Open(fileName)
	Expect(err).NotTo(HaveOccurred())
	fmt.Fscanf(f, "%d %d %d %d %f %f",
		&m.sharedTextSizeK,
		&m.unsharedDataSizeK,
		&m.maxResidentSetSizeK,
		&m.majorPageFaults,
		&m.kernelCPUSecs,
		&m.userCPUSecs,
	)
	err = f.Close()
	Expect(err).NotTo(HaveOccurred())
	return m
}

var summaryTable string

var _ = FContext("with initialized etcd datastore", func() {

	var (
		etcd   *containers.Container
		client *client.Client
	)

	BeforeEach(func() {

		if summaryTable == "" {
			summaryTable = "| Resources | Op | Elapsed time | maxResidentSetSizeK | majorPageFaults | kernelCPUSecs | userCPUSecs |\n|-\n"
		}

		etcd = containers.RunEtcd()

		client = utils.GetEtcdClient(etcd.IP)
		Eventually(client.EnsureInitialized, "10s", "1s").ShouldNot(HaveOccurred())
	})

	AfterEach(func() {

		fmt.Print(summaryTable)

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	configureBGPPeer := func(ii, hostNum int, iiStr, hostStr string) {
		bp := api.NewBGPPeer()
		if ii%2 == 0 {
			bp.Metadata.Scope = scope.Global
		} else {
			bp.Metadata.Scope = scope.Node
			bp.Metadata.Node = hostStr
		}
		bp.Metadata.PeerIP = net.MustParseIP(fmt.Sprintf(
			"10.%d.%d.%d",
			ii/65536,
			(ii/256)%256,
			ii%256,
		))
		bp.Spec.ASNumber = numorstring.ASNumber(65535 - hostNum)
		_, err := client.BGPPeers().Apply(bp)
		Expect(err).NotTo(HaveOccurred())
	}

	configureHostEndpoint := func(ii, hostNum int, iiStr, hostStr string) {
		hep := api.NewHostEndpoint()
		hep.Metadata.Name = "w" + iiStr
		hep.Metadata.Node = "host" + hostStr
		hep.Metadata.Labels = map[string]string{"name": hep.Metadata.Name}
		hep.Spec.InterfaceName = "ens" + iiStr
		hep.Spec.ExpectedIPs = []net.IP{net.MustParseIP(fmt.Sprintf(
			"10.%d.%d.%d",
			ii/65536,
			(ii/256)%256,
			ii%256,
		))}
		hep.Spec.Profiles = []string{"default"}
		_, err := client.HostEndpoints().Apply(hep)
		Expect(err).NotTo(HaveOccurred())
	}

	configureIPPool := func(ii, hostNum int, iiStr, hostStr string) {
		ip := api.NewIPPool()
		ip.Metadata.CIDR = net.MustParseNetwork(fmt.Sprintf(
			"%d.%d.%d.%d/26",
			10+ii/(65536*4),
			(ii/(256*4))%256,
			(ii/4)%256,
			(ii%4)*64,
		))
		ip.Spec.IPIP = &api.IPIPConfiguration{Enabled: true, Mode: ipip.Always}
		ip.Spec.NATOutgoing = false
		ip.Spec.Disabled = true
		_, err := client.IPPools().Apply(ip)
		Expect(err).NotTo(HaveOccurred())
	}

	configureNode := func(ii, hostNum int, iiStr, hostStr string) {
		node := api.NewNode()
		node.Metadata.Name = "n" + iiStr
		asNumber := numorstring.ASNumber(65535 - hostNum)
		ipv4 := net.MustParseNetwork(fmt.Sprintf(
			"10.%d.%d.%d/32",
			ii/65536,
			(ii/256)%256,
			ii%256,
		))
		node.Spec.BGP = &api.NodeBGPSpec{ASNumber: &asNumber, IPv4Address: &ipv4}
		node.Spec.OrchRefs = []api.OrchRef{
			{NodeName: node.Metadata.Name, Orchestrator: "k8s"},
			{NodeName: node.Metadata.Name, Orchestrator: "openstack"},
		}
		_, err := client.Nodes().Apply(node)
		Expect(err).NotTo(HaveOccurred())
	}

	configurePolicy := func(ii, hostNum int, iiStr, hostStr string) {
		policy := api.NewPolicy()
		policy.Metadata.Name = "p" + iiStr
		policy.Metadata.Annotations = map[string]string{"charm": "c" + hostStr}
		order := float64(ii%(hostNum+10)) * 0.37
		if ii%74 != 2 {
			policy.Spec.Order = &order
		}
		ipNet := net.MustParseNetwork(fmt.Sprintf(
			"10.%d.%d.%d/32",
			ii/65536,
			(ii/256)%256,
			ii%256,
		))
		range1, _ := numorstring.PortFromRange(35, 8000)
		range2, _ := numorstring.PortFromRange(8035, 9802)
		entityRule := api.EntityRule{
			Tag:         "t" + hostStr,
			Nets:        []*net.IPNet{&ipNet},
			Selector:    "right=='wrong'",
			Ports:       []numorstring.Port{range1},
			NotTag:      "T" + hostStr,
			NotNets:     []*net.IPNet{&ipNet},
			NotSelector: "right=='left'",
			NotPorts:    []numorstring.Port{range2},
		}
		ipVersion := 4
		tcp := numorstring.ProtocolFromString("tcp")
		udp := numorstring.ProtocolFromString("udp")
		icmpType := 8
		icmpCode := 82
		rule := api.Rule{
			Action:      "allow",
			IPVersion:   &ipVersion,
			Protocol:    &tcp,
			ICMP:        &api.ICMPFields{Type: &icmpType, Code: &icmpCode},
			NotProtocol: &udp,
			NotICMP:     &api.ICMPFields{Type: &icmpType, Code: &icmpCode},
			Source:      entityRule,
			Destination: entityRule,
		}
		policy.Spec.IngressRules = []api.Rule{rule}
		policy.Spec.EgressRules = []api.Rule{rule}
		policy.Spec.Selector = "left=='right'"
		policy.Spec.DoNotTrack = false
		policy.Spec.PreDNAT = false
		policy.Spec.Types = []api.PolicyType{api.PolicyTypeEgress, api.PolicyTypeIngress}
		_, err := client.Policies().Apply(policy)
		Expect(err).NotTo(HaveOccurred())
	}

	configureProfile := func(ii, hostNum int, iiStr, hostStr string) {
		profile := api.NewProfile()
		profile.Metadata.Name = "p" + iiStr
		profile.Metadata.Tags = []string{"c" + hostStr, "t" + iiStr}
		profile.Metadata.Labels = map[string]string{"charm": "c" + hostStr}
		ipNet := net.MustParseNetwork(fmt.Sprintf(
			"10.%d.%d.%d/32",
			ii/65536,
			(ii/256)%256,
			ii%256,
		))
		range1, _ := numorstring.PortFromRange(35, 8000)
		range2, _ := numorstring.PortFromRange(8035, 9802)
		entityRule := api.EntityRule{
			Tag:         "t" + hostStr,
			Net:         &ipNet,
			Selector:    "right=='wrong'",
			Ports:       []numorstring.Port{range1},
			NotTag:      "T" + hostStr,
			NotNet:      &ipNet,
			NotSelector: "right=='left'",
			NotPorts:    []numorstring.Port{range2},
		}
		ipVersion := 4
		tcp := numorstring.ProtocolFromString("tcp")
		udp := numorstring.ProtocolFromString("udp")
		icmpType := 8
		icmpCode := 82
		rule := api.Rule{
			Action:      "allow",
			IPVersion:   &ipVersion,
			Protocol:    &tcp,
			ICMP:        &api.ICMPFields{Type: &icmpType, Code: &icmpCode},
			NotProtocol: &udp,
			NotICMP:     &api.ICMPFields{Type: &icmpType, Code: &icmpCode},
			Source:      entityRule,
			Destination: entityRule,
		}
		profile.Spec.IngressRules = []api.Rule{rule}
		profile.Spec.EgressRules = []api.Rule{rule}
		_, err := client.Profiles().Apply(profile)
		Expect(err).NotTo(HaveOccurred())
	}

	configureWorkloadEndpoint := func(ii, hostNum int, iiStr, hostStr string) {
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
	}

	resourceMap := map[string]func(ii, hostNum int, iiStr, hostStr string){
		"BGPPeer":          configureBGPPeer,
		"HostEndpoint":     configureHostEndpoint,
		"IPPool":           configureIPPool,
		"Node":             configureNode,
		"Policy":           configurePolicy,
		"Profile":          configureProfile,
		"WorkloadEndpoint": configureWorkloadEndpoint,
	}

	plural := func(resourceName string) string {
		if resourceName == "Policy" {
			return "Policies"
		} else {
			return resourceName + "s"
		}
	}

	configureResources := func(resources map[string]int) {
		for resourceName, count := range resources {
			configureFunc := resourceMap[resourceName]
			log.Infof("Configuring %d %s...", count, plural(resourceName))
			checkpoint := time.Now()
			for ii := 0; ii < count; ii++ {
				iiStr := fmt.Sprintf("%06d", ii)
				hostNum := ii % 247
				hostStr := fmt.Sprintf("%04d", hostNum)
				configureFunc(ii, hostNum, iiStr, hostStr)
				if time.Since(checkpoint).Seconds() >= 20 {
					log.Infof("Configured %d %s", ii+1, plural(resourceName))
					checkpoint = time.Now()
				}
			}
			log.Infof("Configured %d %s", count, plural(resourceName))
		}
	}

	const MEASURE_FILE = "timing.txt"
	const MEASURE = "/usr/bin/time -o " + MEASURE_FILE + " -f " + MEASURE_FORMAT
	const CALICO_UPGRADE = "/home/neil/Downloads/calico-upgrade"
	var OUTPUT_DIR = "--output-dir=fv-upgrade-test" + strconv.Itoa(os.Getpid())

	testUpgrade := func(resources map[string]int) {
		description := ""
		for resourceName, count := range resources {
			if description != "" {
				description = description + " "
			}
			description = description + fmt.Sprintf("%d %s", count, plural(resourceName))
		}
		It(description, func() {
			// Configure the specified resources.
			configStart := time.Now()
			configureResources(resources)
			configTime := time.Since(configStart)
			log.Infof("Took %s to configure %s", configTime, description)
			summaryTable += fmt.Sprintf("| %s | Config | %s |\n", description, configTime)

			// Test and time upgrade validation.
			validateStart := time.Now()
			utils.Run("/bin/sh", "-c", fmt.Sprintf(
				"APIV1_ETCD_ENDPOINTS=http://%s:2379 ETCD_ENDPOINTS=http://%s:2379 %s %s dryrun %s",
				etcd.IP,
				etcd.IP,
				MEASURE,
				CALICO_UPGRADE,
				OUTPUT_DIR,
			))
			validateTime := time.Since(validateStart)
			utils.Run("cat", MEASURE_FILE)
			log.Infof("%s", utils.LastRunOutput)
			validateMeasurements := readMeasurements(MEASURE_FILE)
			log.Infof("Took %s, %#v to validate upgrading %s", validateTime, validateMeasurements, description)
			summaryTable += fmt.Sprintf("| | Validate | %s | %d | %d | %.2f | %.2f |\n", validateTime,
				validateMeasurements.maxResidentSetSizeK,
				validateMeasurements.majorPageFaults,
				validateMeasurements.kernelCPUSecs,
				validateMeasurements.userCPUSecs,
			)

			// Test and time actual upgrade.
			convertStart := time.Now()
			utils.Run("/bin/sh", "-c", fmt.Sprintf(
				"echo yes | APIV1_ETCD_ENDPOINTS=http://%s:2379 ETCD_ENDPOINTS=http://%s:2379 %s %s start %s",
				etcd.IP,
				etcd.IP,
				MEASURE,
				CALICO_UPGRADE,
				OUTPUT_DIR,
			))
			convertTime := time.Since(convertStart)
			utils.Run("cat", MEASURE_FILE)
			log.Infof("%s", utils.LastRunOutput)
			convertMeasurements := readMeasurements(MEASURE_FILE)
			log.Infof("Took %s, %#v to upgrade %s", convertTime, convertMeasurements, description)
			summaryTable += fmt.Sprintf("| | Upgrade | %s | %d | %d | %.2f | %.2f |\n", convertTime,
				convertMeasurements.maxResidentSetSizeK,
				convertMeasurements.majorPageFaults,
				convertMeasurements.kernelCPUSecs,
				convertMeasurements.userCPUSecs,
			)
			summaryTable += "|-\n"
		})
	}

	const NUM_RESOURCES = 20000

	testUpgrade(map[string]int{
		"BGPPeer": NUM_RESOURCES,
	})

	testUpgrade(map[string]int{
		"HostEndpoint": NUM_RESOURCES,
	})

	testUpgrade(map[string]int{
		"IPPool": NUM_RESOURCES,
	})

	testUpgrade(map[string]int{
		"Node": NUM_RESOURCES,
	})

	testUpgrade(map[string]int{
		"Policy": NUM_RESOURCES,
	})

	testUpgrade(map[string]int{
		"Profile": NUM_RESOURCES,
	})

	testUpgrade(map[string]int{
		"WorkloadEndpoint": NUM_RESOURCES,
	})
})
