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

	"flag"
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/go/datastructures/set"
	"github.com/projectcalico/calico/go/felix/config"
	"github.com/projectcalico/calico/go/felix/proto"
	"github.com/projectcalico/calico/go/felix/store"
	. "github.com/tigera/libcalico-go/lib/backend/model"
	"github.com/tigera/libcalico-go/lib/net"
	"os"
	"reflect"
	"strings"
)

func init() {
	// FIXME What to do for logs in tests?
	flag.CommandLine.Parse(nil)
	if os.Getenv("GLOG") != "" {
		flag.Lookup("logtostderr").Value.Set("true")
		flag.Lookup("v").Value.Set(os.Getenv("GLOG"))
	}
}

// Canned hostnames.

const localHostname = "localhostname"
const remoteHostname = "remotehostname"

// Canned selectors.

const allSelector = "all()"

var allSelectorId = selectorId(allSelector)

const bEpBSelector = "b == 'b'"

var bEqBSelectorId = selectorId(bEpBSelector)

// Canned workload endpoints.

var localWlEpKey1 = WorkloadEndpointKey{localHostname, "orch", "wl1", "ep1"}
var localWlEpKey2 = WorkloadEndpointKey{localHostname, "orch", "wl2", "ep2"}

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

// Canned tiers/policies.

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

// Pre-defined datastore states.  Each State object wraps up the complete state
// of the datastore as well as the expected state of the dataplane.  The state
// of the dataplane *should* depend only on the current datastore state, not on
// the path taken to get there.  Therefore, it's always a valid test to move
// from any state to any other state (by feeding in the corresponding
// datastore updates) and then assert that the dataplane matches the resulting
// state.

var empty = NewState().withName("<empty>")

var initialisedStore = empty.withKVUpdates(
	KVPair{Key: GlobalConfigKey{Name: "InterfacePrefix"}, Value: "cali"},
	KVPair{Key: ReadyFlagKey{}, Value: true},
).withName("<initialised>")

var withPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: TierKey{"tier-1"}, Value: &tier1},
	KVPair{Key: PolicyKey{Tier: "tier-1", Name: "pol-1"}, Value: &policy1},
).withName("policy")

var localEpsWithPolicy = withPolicy.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
	"10.0.0.3", // ep2
	"fc00:fe11::3",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"tier-1", "pol-1"},
).withName("2 local, overlapping IPs, policy")

var localEp1WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"tier-1", "pol-1"},
).withName("ep1 local, policy")

var localEp2WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
	"10.0.0.3", // ep2
	"fc00:fe11::3",
}).withIPSet(bEqBSelectorId, []string{}).withActivePolicies(
	proto.PolicyID{"tier-1", "pol-1"},
).withName("ep2 local, policy")

// Each entry in baseTests contains a series of states to move through.  Apart
// from running each of these, we'll also expand each of them by passing it
// through the expansion functions below.  In particular, we'll do each of them
// in reversed order and reversed KV injection order.
var baseTests = []StateList{
	// Empty should be empty!
	{},
	// Add one endpoint then remove it and add another with overlapping IP.
	{localEp1WithPolicy, localEp2WithPolicy},
	// Add one endpoint then another with an overlapping IP, then remove
	// first.
	{localEp1WithPolicy, localEpsWithPolicy, localEp2WithPolicy},
	// Add both endpoints, then return to empty, then add them both back.
	{localEpsWithPolicy, initialisedStore, localEpsWithPolicy},
}

type StateList []State

func (l StateList) String() string {
	names := make([]string, 0)
	for _, state := range l {
		names = append(names, state.Name)
	}
	return strings.Join(names, "; ")
}

var testExpanders = []func(baseTest StateList) (desc string, mappedTest StateList){
	identity,
	reverseKVOrder,
	reverseStateOrder,
}

// identity is a test expander that returns the test unaltered.
func identity(baseTest StateList) (desc string, mappedTest StateList) {
	return baseTest.String(), baseTest
}

// reverseStateOrder returns a StateList containing the same states in
// reverse order.
func reverseStateOrder(baseTest StateList) (desc string, mappedTest StateList) {
	for ii := 0; ii < len(baseTest); ii++ {
		mappedTest = append(mappedTest, baseTest[len(baseTest)-ii-1])
	}
	desc = baseTest.String() + " with reversed states"
	return
}

// reverseKVOrder returns a StateList containing the states in the same order
// but with their DataStore key order reversed.
func reverseKVOrder(baseTests StateList) (desc string, mappedTests StateList) {
	desc = baseTests.String() + " with reversed KV order"
	for _, test := range baseTests {
		mappedTest := test.copy()
		state := mappedTest.DatastoreState
		for ii := 0; ii < len(state)/2; ii++ {
			jj := len(state) - ii - 1
			state[ii], state[jj] = state[jj], state[ii]
		}
		mappedTests = append(mappedTests, mappedTest)
	}
	return
}

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

	for _, test := range baseTests {
		for _, expander := range testExpanders {
			desc, test := expander(test)
			// Always worth adding an empty to the end of the test.
			test = append(test, empty)
			It(fmt.Sprintf("should calculate correct dataplane state for: %v", desc), func() {
				lastState := empty
				for ii, state := range test {
					By(fmt.Sprintf("(%v) Moving from state %#v to %#v",
						ii, lastState.Name, state.Name))
					kvDeltas := state.KVDeltas(lastState)
					for _, kv := range kvDeltas {
						fmt.Fprintf(GinkgoWriter, "       -> Injecting KV: %v\n", kv)
						calcGraph.OnUpdate(kv)
					}
					fmt.Fprintln(GinkgoWriter, "       -- <<FLUSH>>")
					eventBuf.Flush()
					Expect(tracker.ipsets).To(Equal(state.ExpectedIPSets),
						"IP sets didn't match expected state after moving to state: %v",
						state.Name)
					Expect(tracker.activePolicies).To(Equal(state.ExpectedPolicyIDs),
						"Active policy IDs were incorrect after moving to state: %v",
						state.Name)
					Expect(tracker.activeProfiles).To(Equal(state.ExpectedProfileIDs),
						"Active profile IDs were incorrect after moving to state: %v",
						state.Name)
					lastState = state
				}
			})
		}
	}
})

type stateTracker struct {
	ipsets         map[string]set.Set
	activePolicies set.Set
	activeProfiles set.Set
}

func newStateTracker() *stateTracker {
	s := &stateTracker{
		ipsets:         make(map[string]set.Set),
		activePolicies: set.New(),
		activeProfiles: set.New(),
	}
	return s
}

func (s *stateTracker) onEvent(event interface{}) {
	evType := reflect.TypeOf(event).String()
	fmt.Fprintf(GinkgoWriter, "       <- Event: %v %v\n", evType, event)
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
			Expect(members.Contains(ip)).To(BeFalse(),
				fmt.Sprintf("IP Set %v already contained IP %v",
					event.Id, ip))
			members.Add(ip)
		}
		for _, ip := range event.RemovedMembers {
			Expect(members.Contains(ip)).To(BeTrue(),
				fmt.Sprintf("IP Set %v did not contain IP %v",
					event.Id, ip))
			members.Discard(ip)
		}
	case *proto.IPSetRemove:
		_, ok := s.ipsets[event.Id]
		if !ok {
			Fail(fmt.Sprintf("IP set remove for unknown ipset %v", event.Id))
			return
		}
		delete(s.ipsets, event.Id)
	case *proto.ActivePolicyUpdate:
		// TODO: check rules against expected rules
		s.activePolicies.Add(*event.Id)
	case *proto.ActivePolicyRemove:
		s.activePolicies.Discard(*event.Id)
	case *proto.ActiveProfileUpdate:
		// TODO: check rules against expected rules
		s.activeProfiles.Add(*event.Id)
	case *proto.ActiveProfileRemove:
		s.activeProfiles.Discard(*event.Id)
	}
}

func (s *stateTracker) UpdateFrom(map[string]string, config.Source) (changed bool, err error) {
	return
}
