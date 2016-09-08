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
	. "github.com/projectcalico/calico/go/felix/calc"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/go/datastructures/multidict"
	"github.com/projectcalico/calico/go/felix/store"
	"github.com/tigera/libcalico-go/lib/backend/model"
	"github.com/golang/glog"
	"github.com/projectcalico/calico/go/felix/config"
	"reflect"
	"github.com/projectcalico/calico/go/felix/proto"
)

// A state represents a particular state of the datastore and the expected
// result of the calculation graph for that state.
type state struct {
	datastoreState []model.KVPair
	expectedIPSets map[string][]string
}

var _ = Describe("Resolver", func() {
	var calcGraph *store.Dispatcher
	var tracker *stateTracker
	var eventBuf *EventBuffer
	BeforeEach(func() {
		tracker = newStateTracker()
		eventBuf = NewEventBuffer(tracker)
		eventBuf.Callback = tracker.onEvent
		calcGraph = NewCalculationGraph(eventBuf, "hostname")
	})

	It("foo", func() {
		_ = NewMemberCalculator()
		Expect("foo").To(Equal("foo"))
	})
})

type stateTracker struct {
	ipsets multidict.StringToIface
	activePolicies map[model.PolicyKey]*ParsedRules
	activeProfiles map[model.ProfileKey]*ParsedRules
}

func newStateTracker() *stateTracker {
	s := &stateTracker{
		ipsets: multidict.NewStringToIface(),
		activePolicies: make(map[model.PolicyKey]*ParsedRules),
		activeProfiles: make(map[model.ProfileKey]*ParsedRules),
	}
	return s
}

func (s *stateTracker) onEvent(event interface{}) {
	glog.Info("Event from event buffer: ", event)
	Expect(event).NotTo(BeNil())
	Expect(reflect.TypeOf(event).Kind()).To(Equal(reflect.Ptr))
	switch event := event.(type) {
	case *proto.IPSetUpdate:
		s.ipsets.DiscardKey(event.Id)
		for _, ip := range event.Members {
			s.ipsets.Put(event.Id, ip)
		}
	case *proto.IPSetDeltaUpdate:
		for _, ip := range event.AddedMembers {
			Expect(s.ipsets.Contains(event.Id, ip)).To(BeFalse())
			s.ipsets.Put(event.Id, ip)
		}
		for _, ip := range event.RemovedMembers {
			Expect(s.ipsets.Contains(event.Id, ip)).To(BeTrue())
			s.ipsets.Discard(event.Id, ip)
		}
	case *proto.IPSetRemove:
		s.ipsets.DiscardKey(event.Id)
	}
}

func (s *stateTracker) UpdateFrom(map[string]string, config.Source) (changed bool, err error) {
	return
}
