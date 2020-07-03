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
	"context"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	options2 "github.com/projectcalico/libcalico-go/lib/options"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/libcalico-go/lib/net"

	. "github.com/projectcalico/felix/fv/connectivity"
	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
)

var _ = describeBPFTestsRepro(withProto("udp"))

func describeBPFTestsRepro(opts ...bpfTestOpt) bool {
	testOpts := bpfTestOptions{
		bpfLogLevel: "debug",
		tunnel:      "none",
	}
	for _, o := range opts {
		o(&testOpts)
	}

	protoExt := ""
	if testOpts.udpUnConnected {
		protoExt = "-unconnected"
	}
	if testOpts.udpConnRecvMsg {
		protoExt = "-conn-recvmsg"
	}

	desc := fmt.Sprintf("_BPF_ _BPF-SAFE_ REPRO BPF tests (%s%s, ct=%v, log=%s, tunnel=%s, dsr=%v)",
		testOpts.protocol, protoExt, testOpts.connTimeEnabled,
		testOpts.bpfLogLevel, testOpts.tunnel, testOpts.dsr,
	)

	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

		var (
			infra          infrastructure.DatastoreInfra
			felixes        []*infrastructure.Felix
			calicoClient   client.Interface
			cc             *Checker
			externalClient *containers.Container
			// bpfLog         *containers.Container
			options        infrastructure.TopologyOptions
			expectedRoutes string
		)

		BeforeEach(func() {
			if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
				Skip("Skipping BPF test in non-BPF run.")
			}
			// bpfLog = containers.Run("bpf-log", containers.RunOpts{AutoRemove: true}, "--privileged",
			//	"calico/bpftool:v5.3-amd64", "/bpftool", "prog", "tracelog")
			infra = getInfra()

			cc = &Checker{
				CheckSNAT: true,
			}
			cc.Protocol = testOpts.protocol
			if testOpts.protocol == "udp" && testOpts.udpUnConnected {
				cc.Protocol += "-noconn"
			}
			if testOpts.protocol == "udp" && testOpts.udpConnRecvMsg {
				cc.Protocol += "-recvmsg"
			}

			options = infrastructure.DefaultTopologyOptions()
			options.FelixLogSeverity = "debug"
			options.NATOutgoingEnabled = true
			switch testOpts.tunnel {
			case "none":
				options.IPIPEnabled = false
				options.IPIPRoutesEnabled = false
				expectedRoutes = expectedRouteDump
			case "ipip":
				options.IPIPEnabled = true
				options.IPIPRoutesEnabled = true
				expectedRoutes = expectedRouteDumpIPIP
			default:
				Fail("bad tunnel option")
			}
			_ = expectedRoutes
			options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancingEnabled"] = fmt.Sprint(testOpts.connTimeEnabled)
			options.ExtraEnvVars["FELIX_BPFLogLevel"] = fmt.Sprint(testOpts.bpfLogLevel)
			if testOpts.dsr {
				options.ExtraEnvVars["FELIX_BPFExternalServiceMode"] = "dsr"
			}
		})

		JustAfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				currBpfsvcs, currBpfeps := dumpNATmaps(felixes)

				for i, felix := range felixes {
					felix.Exec("iptables-save", "-c")
					felix.Exec("ip", "r")
					felix.Exec("ip", "route", "show", "cached")
					felix.Exec("calico-bpf", "ipsets", "dump")
					felix.Exec("calico-bpf", "routes", "dump")
					felix.Exec("calico-bpf", "nat", "dump")
					felix.Exec("calico-bpf", "conntrack", "dump")
					log.Infof("[%d]FrontendMap: %+v", i, currBpfsvcs[i])
					log.Infof("[%d]NATBackend: %+v", i, currBpfeps[i])
					log.Infof("[%d]SendRecvMap: %+v", i, dumpSendRecvMap(felix))
				}
				externalClient.Exec("ip", "route", "show", "cached")
			}
		})

		AfterEach(func() {
			log.Info("AfterEach starting")
			for _, f := range felixes {
				f.Exec("calico-bpf", "connect-time", "clean")
				f.Stop()
			}
			infra.Stop()
			externalClient.Stop()
			// bpfLog.Stop()
			log.Info("AfterEach done")
		})

		createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Creating policy")
			policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}

		updatePolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Updating policy")
			policy, err := calicoClient.GlobalNetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}
		_ = updatePolicy

		const numNodes = 10

		Describe(fmt.Sprintf("with a %d node cluster", numNodes), func() {
			var (
				w      [numNodes][2]*workload.Workload
				hostW  [numNodes]*workload.Workload
				panicC [numNodes]chan struct{}
			)

			BeforeEach(func() {
				felixes, calicoClient = infrastructure.StartNNodeTopology(numNodes, options, infra)

				for i, f := range felixes {
					panicC[i] = f.WatchStderrFor(regexp.MustCompile("panic"))
					go func(i int) {
						defer GinkgoRecover()
						<-panicC[i]
						log.Error("FELIX PANICKED")
						Fail(fmt.Sprintf("Felix %d panicked", i))
					}(i)
				}

				addWorkload := func(run bool, ii, wi, port int, labels map[string]string) *workload.Workload {
					if labels == nil {
						labels = make(map[string]string)
					}

					wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2)
					wName := fmt.Sprintf("w%d%d", ii, wi)

					w := workload.New(felixes[ii], wName, "default",
						wIP, strconv.Itoa(port), testOpts.protocol)
					if run {
						w.Start()
					}

					labels["name"] = w.Name

					w.WorkloadEndpoint.Labels = labels
					w.ConfigureInDatastore(infra)
					// Assign the workload's IP in IPAM, this will trigger calculation of routes.
					err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
						IP:       cnet.MustParseIP(wIP),
						HandleID: &w.Name,
						Attrs: map[string]string{
							ipam.AttributeNode: felixes[ii].Hostname,
						},
						Hostname: felixes[ii].Hostname,
					})
					Expect(err).NotTo(HaveOccurred())

					return w
				}

				// Start a host networked workload on each host for connectivity checks.
				for ii := range felixes {
					// We tell each host-networked workload to open:
					// TODO: Copied from another test
					// - its normal (uninteresting) port, 8055
					// - port 2379, which is both an inbound and an outbound failsafe port
					// - port 22, which is an inbound failsafe port.
					// This allows us to test the interaction between do-not-track policy and failsafe
					// ports.
					hostW[ii] = workload.Run(
						felixes[ii],
						fmt.Sprintf("host%d", ii),
						"default",
						felixes[ii].IP, // Same IP as felix means "run in the host's namespace"
						"8055",
						testOpts.protocol)

					// Two workloads on each host so we can check the same host and other host cases.
					w[ii][0] = addWorkload(true, ii, 0, 8055, map[string]string{"port": "8055"})
					w[ii][1] = addWorkload(true, ii, 1, 8056, nil)
				}

				// Create a workload on node 0 that does not run, but we can use it to set up paths
				_ = addWorkload(false, 0, 2, 8057, nil)

				// We will use this container to model an external client trying to connect into
				// workloads on a host.  Create a route in the container for the workload CIDR.
				// TODO: Copied from another test
				externalClient = containers.Run("external-client",
					containers.RunOpts{AutoRemove: true},
					"--privileged", // So that we can add routes inside the container.
					utils.Config.BusyboxImage,
					"/bin/sh", "-c", "sleep 1000")
				_ = externalClient

				err := infra.AddDefaultDeny()
				Expect(err).NotTo(HaveOccurred())
			})

			Context("with a policy allowing ingress to w[0][0] from all workloads", func() {
				var (
					pol       *api.GlobalNetworkPolicy
					k8sClient *kubernetes.Clientset
				)

				BeforeEach(func() {
					pol = api.NewGlobalNetworkPolicy()
					pol.Namespace = "fv"
					pol.Name = "policy-1"
					pol.Spec.Ingress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "all()",
							},
						},
					}
					pol.Spec.Egress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "all()",
							},
						},
					}
					pol.Spec.Selector = "all()"

					pol = createPolicy(pol)

					k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
					_ = k8sClient
				})

				npPort := uint16(30333)
				nodePortsTest := func(localOnly bool) {
					var (
						testSvc          *v1.Service
						testSvcNamespace string
					)

					testSvcName := "test-service"

					BeforeEach(func() {
						k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
						testSvc = k8sService(testSvcName, "10.101.0.10",
							w[0][0], 80, 8055, int32(npPort), testOpts.protocol)
						if localOnly {
							testSvc.Spec.ExternalTrafficPolicy = "Local"
						}
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(testSvc)
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")
					})

					Describe("after updating the policy to allow traffic from externalClient", func() {
						BeforeEach(func() {
							pol.Spec.Ingress = []api.Rule{
								{
									Action: "Allow",
									Source: api.EntityRule{
										Nets: []string{
											externalClient.IP + "/32",
										},
									},
								},
							}
							pol = updatePolicy(pol)
						})

						It("XXX should have connectivity from external to w[0] via node0", func() {
							go func() {
								defer GinkgoRecover()
								for {
									for i, f := range felixes {
										time.Sleep(time.Duration(rand.Float32() * float32(time.Millisecond*100)))
										n, err := calicoClient.Nodes().Get(context.TODO(), f.Name, options2.GetOptions{})
										Expect(err).NotTo(HaveOccurred())
										n.Spec.OrchRefs = []api.OrchRef{
											{NodeName: f.Name, Orchestrator: fmt.Sprintf("k8s-%d", rand.Uint32())},
										}
										_, _ = calicoClient.Nodes().Update(context.TODO(), n, options2.SetOptions{})
										select {
										case <-panicC[i]:
											break
										default:
										}
									}
								}
							}()
							for {
								for i, f := range felixes {
									time.Sleep(300 * time.Millisecond)
									go func() {
										defer GinkgoRecover()
										f.Restart()
									}()
									select {
									case <-panicC[i]:
										break
									default:
									}
								}
							}
						})
					})
				}

				Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort))+
					" ExternalTrafficPolicy=local", func() {
					nodePortsTest(true)
				})
			})
		})
	})
}
