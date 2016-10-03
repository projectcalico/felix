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
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/tigera/libcalico-go/lib/backend/model"
	"sort"
)

type PolicySorter struct {
	tiers map[string]*TierInfo
}

func NewPolicySorter() *PolicySorter {
	return &PolicySorter{
		tiers: make(map[string]*TierInfo),
	}
}

func (poc *PolicySorter) OnUpdate(update model.KVPair) (dirty bool) {
	switch key := update.Key.(type) {
	case model.TierKey:
		tierName := key.Name
		tierInfo := poc.tiers[tierName]
		if update.Value != nil {
			newTier := update.Value.(*model.Tier)
			if tierInfo == nil {
				tierInfo = NewTierInfo(key.Name)
				poc.tiers[tierName] = tierInfo
				dirty = true
			}
			if tierInfo.Order != newTier.Order {
				tierInfo.Order = newTier.Order
				dirty = true
			}
			tierInfo.Valid = true
		} else {
			// Deletion.
			if tierInfo != nil {
				tierInfo.Valid = false
				if len(tierInfo.Policies) == 0 {
					delete(poc.tiers, tierName)
				}
				dirty = true
			}
		}
	case model.PolicyKey:
		tierInfo := poc.tiers[key.Tier]
		var oldPolicy *model.Policy
		if tierInfo != nil {
			oldPolicy = tierInfo.Policies[key]
		}
		if update.Value != nil {
			newPolicy := update.Value.(*model.Policy)
			if tierInfo == nil {
				tierInfo = NewTierInfo(key.Tier)
				poc.tiers[key.Tier] = tierInfo
			}
			if oldPolicy == nil || oldPolicy.Order != newPolicy.Order {
				dirty = true
			}
			tierInfo.Policies[key] = newPolicy
		} else {
			if oldPolicy != nil {
				delete(tierInfo.Policies, key)
				dirty = true
			}
		}
	}
	return
}

func (poc *PolicySorter) Sorted() []*TierInfo {
	tiers := make([]*TierInfo, 0, len(poc.tiers))
	for _, tier := range poc.tiers {
		tiers = append(tiers, tier)
	}
	sort.Sort(TierByOrder(tiers))
	for _, tierInfo := range poc.tiers {
		tierInfo.OrderedPolicies = make([]PolKV, 0, len(tierInfo.Policies))
		for k, v := range tierInfo.Policies {
			tierInfo.OrderedPolicies = append(tierInfo.OrderedPolicies,
				PolKV{Key: k, Value: v})
		}
		if log.GetLevel() >= log.DebugLevel {
			names := make([]string, len(tierInfo.OrderedPolicies))
			for ii, kv := range tierInfo.OrderedPolicies {
				names[ii] = fmt.Sprintf("%v(%v)",
					kv.Key.Name, *kv.Value.Order)
			}
			log.Infof("Before sorting policies: %v", names)
		}
		sort.Sort(PolicyByOrder(tierInfo.OrderedPolicies))
		if log.GetLevel() >= log.DebugLevel {
			names := make([]string, len(tierInfo.OrderedPolicies))
			for ii, kv := range tierInfo.OrderedPolicies {
				names[ii] = fmt.Sprintf("%v(%v)",
					kv.Key.Name, *kv.Value.Order)
			}
			log.Infof("After sorting policies: %v", names)
		}
	}
	return tiers
}

type TierByOrder []*TierInfo

func (a TierByOrder) Len() int      { return len(a) }
func (a TierByOrder) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a TierByOrder) Less(i, j int) bool {
	if !a[i].Valid {
		return false
	} else if !a[j].Valid {
		return true
	}
	if a[i].Order == nil {
		return false
	} else if a[j].Order == nil {
		return true
	}
	if *a[i].Order == *a[j].Order {
		return a[i].Name < a[j].Name
	}
	return *a[i].Order < *a[j].Order
}

type PolKV struct {
	Key   model.PolicyKey
	Value *model.Policy
}

type PolicyByOrder []PolKV

func (a PolicyByOrder) Len() int      { return len(a) }
func (a PolicyByOrder) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a PolicyByOrder) Less(i, j int) bool {
	bothNil := a[i].Value.Order == nil && a[j].Value.Order == nil
	bothSet := a[i].Value.Order != nil && a[j].Value.Order != nil
	ordersEqual := bothNil || bothSet && (*a[i].Value.Order == *a[j].Value.Order)

	if ordersEqual {
		// Use name as tie-break.
		result := a[i].Key.Name < a[j].Key.Name
		return result
	}

	// nil order maps to "infinity"
	if a[i].Value.Order == nil {
		return false
	} else if a[j].Value.Order == nil {
		return true
	}

	// Otherwise, use numeric comparison.
	return *a[i].Value.Order < *a[j].Value.Order
}

type TierInfo struct {
	Name            string
	Valid           bool
	Order           *float32
	Policies        map[model.PolicyKey]*model.Policy
	OrderedPolicies []PolKV
}

func NewTierInfo(name string) *TierInfo {
	return &TierInfo{
		Name:     name,
		Policies: make(map[model.PolicyKey]*model.Policy),
	}
}

func (t TierInfo) String() string {
	policies := make([]string, len(t.OrderedPolicies))
	for ii, pol := range t.OrderedPolicies {
		policies[ii] = pol.Key.Name
	}
	return fmt.Sprintf("%v -> %v", t.Name, policies)
}
