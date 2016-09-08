// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package fvtest

import (
	. "github.com/projectcalico/calico/go/felix/calc"

	"github.com/golang/glog"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/go/felix/config"
	"github.com/projectcalico/calico/go/felix/proto"
	"github.com/projectcalico/calico/go/felix/store"
	. "github.com/tigera/libcalico-go/lib/backend/model"
	"github.com/tigera/libcalico-go/lib/net"
	net2 "net"
	"reflect"
	"github.com/projectcalico/calico/go/datastructures/set"
	"fmt"
	"flag"
	"os"
	"github.com/tigera/libcalico-go/lib/selector"
)

func init() {
	flag.CommandLine.Parse(nil)
	if os.Getenv("GLOG") != "" {
		flag.Lookup("logtostderr").Value.Set("true")
		flag.Lookup("v").Value.Set(os.Getenv("GLOG"))
	}
}

const localHostname = "localhostname"
const remoteHostname = "remotehostname"

var empty = NewState()

var localWlEpKey1 = WorkloadEndpointKey{localHostname, "orch", "wlid1", "ep1"}
var localWlEpKey2 = WorkloadEndpointKey{localHostname, "orch", "wlid2", "ep2"}

var localWlEp1 = WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
}

var localWlEp2 = WorkloadEndpoint{
	State:      "active",
	Name:       "cali2",
	Mac:        mustParseMac("02:02:03:04:05:06"),
	ProfileIDs: []string{"prof-2", "prof-3"},
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.2/32"),
		mustParseNet("10.0.0.3/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::2/128"),
		mustParseNet("fc00:fe11::3/128")},
	Labels: map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	},
}

var allSelector = "all()"
var allSelectorId = selectorId(allSelector)
var bEpBSelector = "b == 'b'"
var bEqBSelectorId = selectorId(bEpBSelector)

func selectorId(selStr string) string {
	sel, err := selector.Parse(selStr)
	if err != nil {
		glog.Fatalf("Failed to parse %v: %v", selStr, err)
	}
	return sel.UniqueId()
}

var order10 = float32(10)
var order20 = float32(20)
var order30 = float32(30)

var tier1 = Tier{
	Order: &order20,
}

var policy1 = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
		{SrcSelector: bEpBSelector},
	},
	OutboundRules: []Rule{},
}

func mustParseMac(m string) net.MAC {
	hwAddr, err := net2.ParseMAC(m)
	if err != nil {
		glog.Fatalf("Failed to parse MAC: %v; %v", m, err)
	}
	return net.MAC{hwAddr}
}

func mustParseNet(n string) net.IPNet {
	_, cidr, err := net.ParseCIDR(n)
	if err != nil {
		glog.Fatalf("Failed to parse CIDR %v; %v", n, err)
	}
	return *cidr
}

var initialisedStore = State{
	DatastoreState: []KVPair{
		{Key: GlobalConfigKey{Name: "InterfacePrefix"}, Value: "cali"},
		{Key: ReadyFlagKey{}, Value: true},
	},
}

var mainline = initialisedStore.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},

	KVPair{Key: TierKey{"tier-1"}, Value: &tier1},
	KVPair{Key: PolicyKey{"tier-1", "pol-1"}, Value: &policy1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1",  // ep1
	"fc00:fe11::1",
	"10.0.0.2",  // ep1 and ep2
	"fc00:fe11::2",
	"10.0.0.3",  // ep2
	"fc00:fe11::3",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
})

var _ = Describe("Calculation graph", func() {
	var calcGraph *store.Dispatcher
	var tracker *stateTracker
	var eventBuf *EventBuffer
	BeforeEach(func() {
		tracker = newStateTracker()
		eventBuf = NewEventBuffer(tracker)
		eventBuf.Callback = tracker.onEvent
		calcGraph = NewCalculationGraph(eventBuf, localHostname)
	})

	It("should calculate the correct IP sets for the mainline test case", func() {
		glog.Infof("Datastore state: %v", mainline.DatastoreState)
		for _, kv := range mainline.DatastoreState {
			glog.Infof("Injecting KV: %#v", kv)
			calcGraph.OnUpdate(kv)
		}
		eventBuf.Flush()
		Expect(tracker.ipsets).To(Equal(mainline.ExpectedIPSets))
	})
})

type stateTracker struct {
	ipsets         map[string]set.Set
	activePolicies map[PolicyKey]*ParsedRules
	activeProfiles map[ProfileKey]*ParsedRules
}

func newStateTracker() *stateTracker {
	s := &stateTracker{
		ipsets:         make(map[string]set.Set),
		activePolicies: make(map[PolicyKey]*ParsedRules),
		activeProfiles: make(map[ProfileKey]*ParsedRules),
	}
	return s
}

func (s *stateTracker) onEvent(event interface{}) {
	glog.Info("Event from event buffer: ", event)
	Expect(event).NotTo(BeNil())
	Expect(reflect.TypeOf(event).Kind()).To(Equal(reflect.Ptr))
	switch event := event.(type) {
	case *proto.IPSetUpdate:
		newMembers := set.New()
		for _, ip := range event.Members {
			newMembers.Add(ip)
		}
		s.ipsets[event.Id] = newMembers
	case *proto.IPSetDeltaUpdate:
		members, ok := s.ipsets[event.Id]
		if !ok {
			Fail(fmt.Sprintf("IP set delta to missing ipset %v", event.Id))
			return
		}

		for _, ip := range event.AddedMembers {
			Expect(members.Contains(ip)).To(BeFalse())
			members.Add(ip)
		}
		for _, ip := range event.RemovedMembers {
			Expect(members.Contains(ip)).To(BeTrue())
			members.Discard(ip)
		}
	case *proto.IPSetRemove:
		delete(s.ipsets, event.Id)
	}
}

func (s *stateTracker) UpdateFrom(map[string]string, config.Source) (changed bool, err error) {
	return
}
