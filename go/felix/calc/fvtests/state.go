// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package fvtest

import (
	. "github.com/tigera/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/go/datastructures/set"
)

// A state represents a particular state of the datastore and the expected
// result of the calculation graph for that state.
type State struct {
	// List of KVPairs that are in the datastore.  Stored as a list rather
	// than a map to give us a deterministic ordering of injection.
	DatastoreState []KVPair
	ExpectedIPSets map[string]set.Set
}

func NewState() State {
	return State{
		DatastoreState: []KVPair{},
		ExpectedIPSets: make(map[string]set.Set),
	}
}

// copy returns a deep copy of the state.
func (s State) copy() State {
	cpy := NewState()
	cpy.DatastoreState = append(cpy.DatastoreState, s.DatastoreState...)
	for k, ips := range s.ExpectedIPSets {
		cpy.ExpectedIPSets[k] = ips.Copy()
	}
	return cpy
}

// withKVUpdates returns a deep copy of the state, incorporating the passed KVs.
// If a new KV is an update to an existing KV, the existing KV is discarded and
// the new KV is appended.  If the value of a new KV is nil, it is removed.
func (s State) withKVUpdates(kvs ...KVPair) (newState State) {
	// Start with a clean copy.
	newState = s.copy()
	// But replace the datastoreState, which we're about to modify.
	newState.DatastoreState = make([]KVPair, 0, len(kvs)+len(s.DatastoreState))
	// Make a set containing the new keys.
	newKeys := make(map[Key]bool)
	for _, kv := range kvs {
		newKeys[kv.Key] = true
	}
	// Copy across the old KVs, skipping ones that are in the updates set.
	for _, kv := range s.DatastoreState {
		if newKeys[kv.Key] {
			continue
		}
		newState.DatastoreState = append(newState.DatastoreState, kv)
	}
	// Copy in the updates in order.
	for _, kv := range kvs {
		if kv.Value == nil {
			continue
		}
		newState.DatastoreState = append(newState.DatastoreState, kv)
	}
	return
}

func (s State) withIPSet(name string, members []string) (newState State) {
	// Start with a clean copy.
	newState = s.copy()
	if members == nil {
		delete(newState.ExpectedIPSets, name)
	} else {
		set := set.New()
		for _, ip := range members {
			set.Add(ip)
		}
		newState.ExpectedIPSets[name] = set
	}
	return
}
