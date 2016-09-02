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

package endpoint

import (
	"github.com/golang/glog"
	"github.com/projectcalico/calico/go/datastructures/multidict"
	"github.com/projectcalico/calico/go/datastructures/set"
	"github.com/tigera/libcalico-go/lib/backend/api"
	"github.com/tigera/libcalico-go/lib/backend/model"
)

type PolicyResolver struct {
	policyIDToEndpointIDs multidict.IfaceToIface
	endpointIDToPolicyIDs multidict.IfaceToIface
	sortedTierData        []*TierInfo
	endpoints             map[model.Key]interface{}
	dirtyEndpoints        set.Set
	sortRequired          bool
	policySorter          *PolicySorter
	Callbacks             PolicyResolverCallbacks
	InSync                bool
}

type PolicyResolverCallbacks interface {
	OnEndpointTierUpdate(endpointKey model.Key, endpoint interface{}, filteredTiers []TierInfo)
}

func NewPolicyResolver() *PolicyResolver {
	return &PolicyResolver{
		policyIDToEndpointIDs: multidict.NewIfaceToIface(),
		endpointIDToPolicyIDs: multidict.NewIfaceToIface(),
		endpoints:             make(map[model.Key]interface{}),
		dirtyEndpoints:        set.New(),
		policySorter:          NewPolicySorter(),
	}
}

func (pr *PolicyResolver) OnUpdate(update model.KVPair) (filterOut bool) {
	policiesDirty := false
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey, model.HostEndpointKey:
		if update.Value != nil {
			pr.endpoints[key] = update.Value
		} else {
			delete(pr.endpoints, key)
		}
		pr.dirtyEndpoints.Add(key)
	case model.PolicyKey:
		glog.V(3).Infof("Policy update: %v", key)
		policiesDirty = pr.policySorter.OnUpdate(update)
		pr.markEndpointsMatchingPolicyDirty(key)
	case model.TierKey:
		glog.V(3).Infof("Tier update: %v", key)
		policiesDirty = pr.policySorter.OnUpdate(update)
		pr.markAllEndpointsDirty()
	}
	pr.sortRequired = pr.sortRequired || policiesDirty
	pr.maybeFlush()
	return
}

func (pr *PolicyResolver) OnDatamodelStatus(status api.SyncStatus) {
	if status == api.InSync {
		pr.InSync = true
		pr.maybeFlush()
	}
}

func (pr *PolicyResolver) refreshSortOrder() {
	pr.sortedTierData = pr.policySorter.Sorted()
	pr.sortRequired = false
	glog.V(3).Infof("New sort order: %v", pr.sortedTierData)
}

func (pr *PolicyResolver) markAllEndpointsDirty() {
	glog.V(3).Infof("Marking all endpoints dirty")
	pr.endpointIDToPolicyIDs.IterKeys(func(epID interface{}) {
		pr.dirtyEndpoints.Add(epID)
	})
}

func (pr *PolicyResolver) markEndpointsMatchingPolicyDirty(polKey model.PolicyKey) {
	glog.V(3).Infof("Marking all endpoints matching %v dirty", polKey)
	pr.policyIDToEndpointIDs.Iter(polKey, func(epID interface{}) {
		pr.dirtyEndpoints.Add(epID)
	})
}

func (pr *PolicyResolver) OnPolicyMatch(policyKey model.PolicyKey, endpointKey interface{}) {
	glog.V(3).Infof("Storing policy match %v -> %v", policyKey, endpointKey)
	pr.policyIDToEndpointIDs.Put(policyKey, endpointKey)
	pr.endpointIDToPolicyIDs.Put(endpointKey, policyKey)
	pr.dirtyEndpoints.Add(endpointKey)
	pr.maybeFlush()
}

func (pr *PolicyResolver) OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey interface{}) {
	glog.V(3).Infof("Deleting policy match %v -> %v", policyKey, endpointKey)
	pr.policyIDToEndpointIDs.Discard(policyKey, endpointKey)
	pr.endpointIDToPolicyIDs.Discard(endpointKey, policyKey)
	pr.dirtyEndpoints.Add(endpointKey)
	pr.maybeFlush()
}

func (pr *PolicyResolver) maybeFlush() {
	if !pr.InSync {
		glog.V(3).Infof("Not in sync, skipping flush")
		return
	}
	if pr.sortRequired {
		pr.refreshSortOrder()
	}
	pr.dirtyEndpoints.Iter(pr.sendEndpointUpdate)
	pr.dirtyEndpoints = set.New()
}

func (pr *PolicyResolver) sendEndpointUpdate(endpointID interface{}) error {
	glog.V(3).Infof("Sending tier update for endpoint %v", endpointID)
	endpoint, ok := pr.endpoints[endpointID.(model.Key)]
	if !ok {
		glog.V(4).Infof("Endpoint is unknown, sending nil update")
		pr.Callbacks.OnEndpointTierUpdate(endpointID.(model.Key),
			nil, []TierInfo{})
		return nil
	}
	applicableTiers := []TierInfo{}
	for _, tier := range pr.sortedTierData {
		if !tier.Valid {
			glog.V(3).Infof("Tier %v invalid, skipping", tier.Name)
			continue
		}
		tierMatches := false
		filteredTier := TierInfo{
			Name:  tier.Name,
			Order: tier.Order,
			Valid: true,
		}
		for _, polKV := range tier.OrderedPolicies {
			glog.V(4).Infof("Checking if policy %v matches %v", polKV.Key, endpointID)
			if pr.endpointIDToPolicyIDs.Contains(endpointID, polKV.Key) {
				glog.V(4).Infof("Policy %v matches %v", polKV.Key, endpointID)
				tierMatches = true
				filteredTier.OrderedPolicies = append(filteredTier.OrderedPolicies,
					polKV)
			}
		}
		if tierMatches {
			glog.V(4).Infof("Tier %v matches %v", tier.Name, endpointID)
			applicableTiers = append(applicableTiers, filteredTier)
		}
	}
	glog.V(4).Infof("Endpoint tier update: %v -> %v", endpointID, applicableTiers)
	pr.Callbacks.OnEndpointTierUpdate(endpointID.(model.Key),
		endpoint, applicableTiers)
	return nil
}
