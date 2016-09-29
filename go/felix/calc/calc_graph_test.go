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

package calc_test

import (
	. "github.com/projectcalico/felix/go/felix/calc"

	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/go/datastructures/set"
	"github.com/projectcalico/felix/go/felix/config"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/store"
	"github.com/tigera/libcalico-go/lib/backend/api"
	. "github.com/tigera/libcalico-go/lib/backend/model"
	"github.com/tigera/libcalico-go/lib/net"
	"reflect"
	"strings"
)

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
var localWlEp1Id = "orch/wl1/ep1"
var localWlEpKey2 = WorkloadEndpointKey{localHostname, "orch", "wl2", "ep2"}
var localWlEp2Id = "orch/wl2/ep2"

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

var ep1IPs = []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // shared with ep2
	"fc00:fe11::2",
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

var hostEpWithName = HostEndpoint{
	Name:       "eth1",
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	ExpectedIPv4Addrs: []net.IP{mustParseIP("10.0.0.1"),
		mustParseIP("10.0.0.2")},
	ExpectedIPv6Addrs: []net.IP{mustParseIP("fc00:fe11::1"),
		mustParseIP("fc00:fe11::2")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
}

var hostEpWithNameKey = HostEndpointKey{
	Hostname:   localHostname,
	EndpointID: "named",
}
var hostEpWithNameId = "named"

var hostEp2NoName = HostEndpoint{
	ProfileIDs: []string{"prof-2", "prof-3"},
	ExpectedIPv4Addrs: []net.IP{mustParseIP("10.0.0.2"),
		mustParseIP("10.0.0.3")},
	ExpectedIPv6Addrs: []net.IP{mustParseIP("fc00:fe11::2"),
		mustParseIP("fc00:fe11::3")},
	Labels: map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	},
}

var hostEp2NoNameKey = HostEndpointKey{
	Hostname:   localHostname,
	EndpointID: "unnamed",
}
var hostEpNoNameId = "unnamed"

// Canned tiers/policies.

var order10 = float32(10)
var order20 = float32(20)
var order30 = float32(30)

var tier1_order10 = Tier{
	Order: &order10,
}

var tier1_order20 = Tier{
	Order: &order20,
}

var tier1_order30 = Tier{
	Order: &order30,
}

var policy1_order10 = Policy{
	Order:    &order10,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
}

var policy1_order20 = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
}

var policy1_order30 = Policy{
	Order:    &order30,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
}

var profileRules1 = ProfileRules{
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcTag: "tag-1"},
	},
}

var profileRules1TagUpdate = ProfileRules{
	InboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	OutboundRules: []Rule{
		{SrcTag: "tag-2"},
	},
}

var profileTags1 = []string{"tag-1"}
var profileLabels1 = map[string]string{
	"profile": "prof-1",
}
var tag1LabelId = TagIPSetID("tag-1")
var tag2LabelId = TagIPSetID("tag-2")

// Pre-defined datastore states.  Each State object wraps up the complete state
// of the datastore as well as the expected state of the dataplane.  The state
// of the dataplane *should* depend only on the current datastore state, not on
// the path taken to get there.  Therefore, it's always a valid test to move
// from any state to any other state (by feeding in the corresponding
// datastore updates) and then assert that the dataplane matches the resulting
// state.

// empty is the base state, with nothing in the datastore or dataplane.
var empty = NewState().withName("<empty>")

// initialisedStore builds on empty, adding in the ready flag and global config.
var initialisedStore = empty.withKVUpdates(
	KVPair{Key: GlobalConfigKey{Name: "InterfacePrefix"}, Value: "cali"},
	KVPair{Key: ReadyFlagKey{}, Value: true},
).withName("<initialised>")

// withPolicy adds a tier and policy containing selectors for all and b=="b"
var withPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: TierKey{"tier-1"}, Value: &tier1_order20},
	KVPair{Key: PolicyKey{Tier: "tier-1", Name: "pol-1"}, Value: &policy1_order20},
).withName("with policy")

// localEp1WithPolicy adds a local endpoint to the mix.  It matches all and b=="b".
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
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{
		{"tier-1", []string{"pol-1"}},
	},
).withName("ep1 local, policy")

var hostEp1WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
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
).withEndpoint(
	hostEpWithNameId,
	[]tierInfo{
		{"tier-1", []string{"pol-1"}},
	},
).withName("host ep1, policy")

var hostEp2WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: hostEp2NoNameKey, Value: &hostEp2NoName},
).withIPSet(allSelectorId, []string{
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
	"10.0.0.3", // ep2
	"fc00:fe11::3",
}).withIPSet(bEqBSelectorId, []string{}).withActivePolicies(
	proto.PolicyID{"tier-1", "pol-1"},
).withEndpoint(
	hostEpNoNameId,
	[]tierInfo{
		{"tier-1", []string{"pol-1"}},
	},
).withName("host ep2, policy")

// Policy ordering tests.  We keep the names of the policies the same but we
// change their orders to check that order trumps name.
var localEp1WithOneTierPolicy123 = policyOrderState(
	[3]float32{order10, order20, order30},
	[3]string{"pol-1", "pol-2", "pol-3"},
)
var localEp1WithOneTierPolicy321 = policyOrderState(
	[3]float32{order30, order20, order10},
	[3]string{"pol-3", "pol-2", "pol-1"},
)
var localEp1WithOneTierPolicyAlpha = policyOrderState(
	[3]float32{order10, order10, order10},
	[3]string{"pol-1", "pol-2", "pol-3"},
)

func policyOrderState(policyOrders [3]float32, expectedOrder [3]string) State {
	policies := [3]Policy{}
	for i := range policies {
		policies[i] = Policy{
			Order:         &policyOrders[i],
			Selector:      "a == 'a'",
			InboundRules:  []Rule{{SrcSelector: allSelector}},
			OutboundRules: []Rule{{SrcSelector: bEpBSelector}},
		}
	}
	state := initialisedStore.withKVUpdates(
		KVPair{Key: localWlEpKey1, Value: &localWlEp1},
		KVPair{Key: TierKey{"tier-1"}, Value: &tier1_order20},
		KVPair{Key: PolicyKey{Tier: "tier-1", Name: "pol-1"}, Value: &policies[0]},
		KVPair{Key: PolicyKey{Tier: "tier-1", Name: "pol-2"}, Value: &policies[1]},
		KVPair{Key: PolicyKey{Tier: "tier-1", Name: "pol-3"}, Value: &policies[2]},
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
		proto.PolicyID{"tier-1", "pol-2"},
		proto.PolicyID{"tier-1", "pol-3"},
	).withEndpoint(
		localWlEp1Id,
		[]tierInfo{
			{"tier-1", expectedOrder[:]},
		},
	).withName(fmt.Sprintf("ep1 local, 1 tier, policies %v", expectedOrder[:]))
	return state
}

// Tier ordering tests.  We keep the names of the tiers constant but adjust
// their orders.
var localEp1WithTiers123 = tierOrderState(
	[3]float32{order10, order20, order30},
	[3]string{"tier-1", "tier-2", "tier-3"},
)
var localEp1WithTiers321 = tierOrderState(
	[3]float32{order30, order20, order10},
	[3]string{"tier-3", "tier-2", "tier-1"},
)

// These tests use the same order for each tier, checking that the name is
// used as a tie breaker.
var localEp1WithTiersAlpha = tierOrderState(
	[3]float32{order10, order10, order10},
	[3]string{"tier-1", "tier-2", "tier-3"},
)
var localEp1WithTiersAlpha2 = tierOrderState(
	[3]float32{order20, order20, order20},
	[3]string{"tier-1", "tier-2", "tier-3"},
)
var localEp1WithTiersAlpha3 = tierOrderState(
	[3]float32{order20, order20, order10},
	[3]string{"tier-3", "tier-1", "tier-2"},
)

func tierOrderState(tierOrders [3]float32, expectedOrder [3]string) State {
	tiers := [3]Tier{}
	for i := range tiers {
		tiers[i] = Tier{
			Order: &tierOrders[i],
		}
	}
	state := initialisedStore.withKVUpdates(
		KVPair{Key: localWlEpKey1, Value: &localWlEp1},
		KVPair{Key: TierKey{"tier-1"}, Value: &tiers[0]},
		KVPair{Key: PolicyKey{Tier: "tier-1", Name: "tier-1-pol"}, Value: &policy1_order20},
		KVPair{Key: TierKey{"tier-2"}, Value: &tiers[1]},
		KVPair{Key: PolicyKey{Tier: "tier-2", Name: "tier-2-pol"}, Value: &policy1_order20},
		KVPair{Key: TierKey{"tier-3"}, Value: &tiers[2]},
		KVPair{Key: PolicyKey{Tier: "tier-3", Name: "tier-3-pol"}, Value: &policy1_order20},
	).withIPSet(
		allSelectorId, ep1IPs,
	).withIPSet(
		bEqBSelectorId, ep1IPs,
	).withActivePolicies(
		proto.PolicyID{"tier-1", "tier-1-pol"},
		proto.PolicyID{"tier-2", "tier-2-pol"},
		proto.PolicyID{"tier-3", "tier-3-pol"},
	).withEndpoint(
		localWlEp1Id,
		[]tierInfo{
			{expectedOrder[0], []string{expectedOrder[0] + "-pol"}},
			{expectedOrder[1], []string{expectedOrder[1] + "-pol"}},
			{expectedOrder[2], []string{expectedOrder[2] + "-pol"}},
		},
	).withName(fmt.Sprintf("ep1 local, tiers %v", expectedOrder[:]))
	return state
}

// localEp2WithPolicy adds a different endpoint that doesn't match b=="b".
// This tests an empty IP set.
var localEp2WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
	"10.0.0.3", // ep2
	"fc00:fe11::3",
}).withIPSet(
	bEqBSelectorId, []string{},
).withActivePolicies(
	proto.PolicyID{"tier-1", "pol-1"},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{
		{"tier-1", []string{"pol-1"}},
	},
).withName("ep2 local, policy")

// localEpsWithPolicy contains both of the above endpoints, which have some
// overlapping IPs.  When we sequence this with the states above, we test
// overlapping IP addition and removal.
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
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{
		{"tier-1", []string{"pol-1"}},
	},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{
		{"tier-1", []string{"pol-1"}},
	},
).withName("2 local, overlapping IPs & a policy")

// withProfile adds a profile to the initialised state.
var withProfile = initialisedStore.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey{"prof-1"}}, Value: &profileRules1},
	KVPair{Key: ProfileTagsKey{ProfileKey{"prof-1"}}, Value: profileTags1},
	KVPair{Key: ProfileLabelsKey{ProfileKey{"prof-1"}}, Value: profileLabels1},
).withName("profile")

// localEpsWithProfile contains a pair of overlapping IP endpoints and a profile
// that matches them both.
var localEpsWithProfile = withProfile.withKVUpdates(
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
}).withIPSet(tag1LabelId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withActiveProfiles(
	proto.ProfileID{"prof-1"},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{},
).withName("2 local, overlapping IPs & a profile")

// localEpsWithUpdatedProfile Follows on from localEpsWithProfile, changing the
// profile to use a different tag and selector.
var localEpsWithUpdatedProfile = localEpsWithProfile.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey{"prof-1"}}, Value: &profileRules1TagUpdate},
).withIPSet(
	tag1LabelId, nil,
).withIPSet(
	allSelectorId, nil,
).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withIPSet(
	tag2LabelId, []string{},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{},
).withName("2 local, overlapping IPs & updated profile")

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

	// Add a profile and a couple of endpoints.  Then update the profile to
	// use different tags and selectors.
	{localEpsWithProfile, localEpsWithUpdatedProfile},

	// Tests of policy ordering.  Each state has one tier but we shuffle
	// the order of the policies within it.
	{localEp1WithOneTierPolicy123,
		localEp1WithOneTierPolicy321,
		localEp1WithOneTierPolicyAlpha},

	// And tier ordering.
	{localEp1WithTiers123,
		localEp1WithTiers321,
		localEp1WithTiersAlpha,
		localEp1WithTiersAlpha2,
		localEp1WithTiers321,
		localEp1WithTiersAlpha3},

	// String together some complex updates with profiles and policies
	// coming and going.
	{localEpsWithProfile,
		localEp1WithOneTierPolicy123,
		localEp1WithTiers321,
		localEpsWithPolicy,
		localEpsWithUpdatedProfile,
		localEp1WithPolicy,
		localEp1WithTiersAlpha2,
		localEpsWithProfile},

	// Host endpoint tests.
	{hostEp1WithPolicy, hostEp2WithPolicy},
}

type StateList []State

func (l StateList) String() string {
	names := make([]string, 0)
	for _, state := range l {
		names = append(names, state.String())
	}
	return "[" + strings.Join(names, ", ") + "]"
}

var testExpanders = []func(baseTest StateList) (desc string, mappedTest StateList){
	identity,
	reverseKVOrder,
	reverseStateOrder,
	squash,
}

// identity is a test expander that returns the test unaltered.
func identity(baseTest StateList) (string, StateList) {
	return "in normal ordering", baseTest
}

// reverseStateOrder returns a StateList containing the same states in
// reverse order.
func reverseStateOrder(baseTest StateList) (desc string, mappedTest StateList) {
	for ii := 0; ii < len(baseTest); ii++ {
		mappedTest = append(mappedTest, baseTest[len(baseTest)-ii-1])
	}
	desc = "with order of states reversed"
	return
}

// reverseKVOrder returns a StateList containing the states in the same order
// but with their DataStore key order reversed.
func reverseKVOrder(baseTests StateList) (desc string, mappedTests StateList) {
	desc = "with order of KVs reversed within each state"
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

// squash returns a StateList with all the states squashed into one (which may
// include some deletions in the DatastoreState.
func squash(baseTests StateList) (desc string, mappedTests StateList) {
	desc = "all states squashed into one"
	if len(baseTests) == 0 {
		return
	}
	kvs := make([]KVPair, 0)
	mappedTest := baseTests[len(baseTests)-1].copy()
	lastTest := empty
	for _, test := range baseTests {
		kvs = append(kvs, test.KVDeltas(lastTest)...)
		lastTest = test
	}
	mappedTest.DatastoreState = kvs
	mappedTest.ExpectedEndpointPolicyOrder = lastTest.ExpectedEndpointPolicyOrder
	mappedTest.Name = fmt.Sprintf("squashed(%v)", baseTests)
	mappedTests = append(mappedTests, mappedTest)
	return
}

var _ = Describe("Calculation graph", func() {
	for _, test := range baseTests {
		test := test
		for _, expander := range testExpanders {
			desc, expandedTest := expander(test)
			// Always worth adding an empty to the end of the test.
			expandedTest = append(expandedTest, empty)
			Describe(fmt.Sprintf("with input states %v %v", test, desc), func() {
				var validationFilter *ValidationFilter
				var calcGraph *store.Dispatcher
				var tracker *stateTracker
				var eventBuf *EventBuffer
				var lastState State
				var state State

				BeforeEach(func() {
					tracker = newStateTracker()
					eventBuf = NewEventBuffer(tracker)
					eventBuf.Callback = tracker.onEvent
					calcGraph = NewCalculationGraph(eventBuf, localHostname)
					validationFilter = NewValidationFilter(calcGraph)
					validationFilter.OnStatusUpdated(api.InSync)
					lastState = empty
					state = empty
				})

				// iterStates iterates through the states in turn,
				// executing the expectation function after each
				// state.
				iterStates := func(expectation func()) func() {
					return func() {
						var ii int
						for ii, state = range expandedTest {
							By(fmt.Sprintf("(%v) Moving from state %#v to %#v",
								ii, lastState.Name, state.Name))
							kvDeltas := state.KVDeltas(lastState)
							for _, kv := range kvDeltas {
								fmt.Fprintf(GinkgoWriter, "       -> Injecting KV: %v\n", kv)
								validationFilter.OnUpdates([]KVPair{kv})
							}
							fmt.Fprintln(GinkgoWriter, "       -- <<FLUSH>>")
							eventBuf.Flush()
							expectation()
							lastState = state
						}
					}
				}

				It("should calculate correct IP sets", iterStates(func() {
					Expect(tracker.ipsets).To(Equal(state.ExpectedIPSets),
						"IP sets didn't match expected state after moving to state: %v",
						state.Name)
				}))
				It("should calculate correct active policies", iterStates(func() {
					Expect(tracker.activePolicies).To(Equal(state.ExpectedPolicyIDs),
						"Active policy IDs were incorrect after moving to state: %v",
						state.Name)
				}))
				It("should calculate correct active profiles", iterStates(func() {
					Expect(tracker.activeProfiles).To(Equal(state.ExpectedProfileIDs),
						"Active profile IDs were incorrect after moving to state: %v",
						state.Name)
				}))
				It("should calculate correct policies", iterStates(func() {
					Expect(tracker.endpointToPolicyOrder).To(Equal(state.ExpectedEndpointPolicyOrder),
						"Endpoint policy order incorrect after moving to state: %v",
						state.Name)
				}))
			})
		}
	}
})

type stateTracker struct {
	ipsets                map[string]set.Set
	activePolicies        set.Set
	activeProfiles        set.Set
	endpointToPolicyOrder map[string][]tierInfo
	config                map[string]string
}

func newStateTracker() *stateTracker {
	s := &stateTracker{
		ipsets:                make(map[string]set.Set),
		activePolicies:        set.New(),
		activeProfiles:        set.New(),
		endpointToPolicyOrder: make(map[string][]tierInfo),
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
				fmt.Sprintf("IP Set %v already contained added IP %v",
					event.Id, ip))
			members.Add(ip)
		}
		for _, ip := range event.RemovedMembers {
			Expect(members.Contains(ip)).To(BeTrue(),
				fmt.Sprintf("IP Set %v did not contain removed IP %v",
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
	case *proto.WorkloadEndpointUpdate:
		tiers := event.Endpoint.Tiers
		tierInfos := make([]tierInfo, len(tiers))
		for i, tier := range tiers {
			tierInfos[i].Name = tier.Name
			tierInfos[i].PolicyNames = tier.Policies
		}
		id := workloadId(*event.Id)
		s.endpointToPolicyOrder[id.String()] = tierInfos
	case *proto.WorkloadEndpointRemove:
		id := workloadId(*event.Id)
		delete(s.endpointToPolicyOrder, id.String())
	case *proto.HostEndpointUpdate:
		tiers := event.Endpoint.Tiers
		tierInfos := make([]tierInfo, len(tiers))
		for i, tier := range tiers {
			tierInfos[i].Name = tier.Name
			tierInfos[i].PolicyNames = tier.Policies
		}
		id := hostEpId(*event.Id)
		s.endpointToPolicyOrder[id.String()] = tierInfos
	case *proto.HostEndpointRemove:
		id := hostEpId(*event.Id)
		delete(s.endpointToPolicyOrder, id.String())
	}
}

func (s *stateTracker) UpdateFrom(map[string]string, config.Source) (changed bool, err error) {
	return
}

func (s *stateTracker) RawValues() map[string]string {
	return s.config
}

type tierInfo struct {
	Name        string
	PolicyNames []string
}

type workloadId proto.WorkloadEndpointID

func (w *workloadId) String() string {
	return fmt.Sprintf("%v/%v/%v",
		w.OrchestratorId, w.WorkloadId, w.EndpointId)
}

type hostEpId proto.HostEndpointID

func (i *hostEpId) String() string {
	return i.EndpointId
}
