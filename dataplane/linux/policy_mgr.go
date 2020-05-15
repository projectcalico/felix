// Copyright (c) 2016-2017, 2019-2020 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
)

type policyManagerCallbacks struct {
	updatePolicy *UpdatePolicyDataFuncs
	removePolicy *RemovePolicyDataFuncs
}

func newPolicyManagerCallbacks(callbacks *callbacks, ipVersion uint8) policyManagerCallbacks {
	if ipVersion == 4 {
		return policyManagerCallbacks{
			updatePolicy: callbacks.UpdatePolicyV4,
			removePolicy: callbacks.RemovePolicyV4,
		}
	} else {
		return policyManagerCallbacks{
			updatePolicy: &UpdatePolicyDataFuncs{},
			removePolicy: &RemovePolicyDataFuncs{},
		}
	}
}

func (c *policyManagerCallbacks) InvokeUpdatePolicy(policyID proto.PolicyID, policy *proto.Policy) {
	c.updatePolicy.Invoke(policyID, policy)
}

func (c *policyManagerCallbacks) InvokeRemovePolicy(policyID proto.PolicyID) {
	c.removePolicy.Invoke(policyID)
}

// policyManager does refcounting per policy and iptables table and programs the policy's chains
// into the tables where it is referenced by an endpoint.
//
// Workload endpoint policy always goes in the filter chain only. Host endpoint policy varies by type.
// Profiles only go in the filter table so they are passed through without refcounting.
type policyManager struct {
	tables map[iptables.TableName]iptablesTable

	ruleRenderer policyRenderer
	ipVersion    uint8
	callbacks    policyManagerCallbacks

	// Caches of endpoints so that we can decref the correct policies when an endpoint is
	// removed or updated.

	wepsByID map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	hepsByID map[proto.HostEndpointID]*proto.HostEndpoint

	// policyRefCounts stores a map of refcounts per policy.  perTableRefcounts holds a value per table
	policyRefCounts map[proto.PolicyID]perTableRefcounts
	policiesByID    map[proto.PolicyID]*proto.Policy
}

type perTableRefcounts map[iptables.TableName]int

type policyRenderer interface {
	PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*iptables.Chain
	ProfileToIptablesChains(profileID *proto.ProfileID, policy *proto.Profile, ipVersion uint8) []*iptables.Chain
}

func newPolicyManager(rawTable, mangleTable, filterTable iptablesTable, ruleRenderer policyRenderer, ipVersion uint8, callbacks *callbacks) *policyManager {
	return &policyManager{
		tables: map[iptables.TableName]iptablesTable{
			iptables.TableRaw:    rawTable,
			iptables.TableMangle: mangleTable,
			iptables.TableFilter: filterTable,
		},
		ruleRenderer: ruleRenderer,
		ipVersion:    ipVersion,
		callbacks:    newPolicyManagerCallbacks(callbacks, ipVersion),

		wepsByID: map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		hepsByID: map[proto.HostEndpointID]*proto.HostEndpoint{},

		policyRefCounts: map[proto.PolicyID]perTableRefcounts{},
		policiesByID:    map[proto.PolicyID]*proto.Policy{},
	}
}

func (m *policyManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.WorkloadEndpointUpdate:
		m.onWorkloadEndpointUpdate(msg)
	case *proto.WorkloadEndpointRemove:
		m.onWorkloadEndpointRemove(msg)
	case *proto.HostEndpointUpdate:
		m.onHostEndpointUpdate(msg)
	case *proto.HostEndpointRemove:
		m.onHostEndpointRemove(msg)

	case *proto.ActivePolicyUpdate:
		m.onPolicyUpdate(msg)
	case *proto.ActivePolicyRemove:
		m.onPolicyRemove(msg)
	case *proto.ActiveProfileUpdate:
		m.onProfileUpdate(msg)
	case *proto.ActiveProfileRemove:
		m.onProfileRemove(msg)
	}
}

func (m *policyManager) onWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate) {
	id := *msg.Id

	// Incref the new endpoint first, triggering and new policies to be programmed.
	newWep := msg.Endpoint
	m.increfTier(newWep.Tiers, iptables.TableFilter) // Workload policy lives only in filter.

	// Decref the old endpoint.  Any policies that are not also in the new wep will
	// hit 0 and be removed.
	m.removeWep(id)

	// Store off the new wep.
	m.wepsByID[id] = newWep
}

func (m *policyManager) onWorkloadEndpointRemove(msg *proto.WorkloadEndpointRemove) {
	m.removeWep(*msg.Id)
}

func (m *policyManager) removeWep(id proto.WorkloadEndpointID) {
	if oldWep := m.wepsByID[id]; oldWep != nil {
		tier := oldWep.Tiers
		m.decrefTier(tier, iptables.TableFilter)
		delete(m.wepsByID, id)
	}
}

func (m *policyManager) onHostEndpointUpdate(msg *proto.HostEndpointUpdate) {
	id := *msg.Id

	// Incref the new endpoint first, triggering and new policies to be programmed.
	newHep := msg.Endpoint
	m.increfTier(newHep.Tiers, iptables.TableFilter)
	m.increfTier(newHep.ForwardTiers, iptables.TableFilter)
	m.increfTier(newHep.PreDnatTiers, iptables.TableMangle)
	m.increfTier(newHep.UntrackedTiers, iptables.TableRaw)

	// Decref the old endpoint.  Any policies that are not also in the new hep will
	// hit 0 and be removed.
	m.removeHep(id)

	// Store off the new hep.
	m.hepsByID[id] = newHep
}

func (m *policyManager) onHostEndpointRemove(msg *proto.HostEndpointRemove) {
	m.removeHep(*msg.Id)
}

func (m *policyManager) removeHep(id proto.HostEndpointID) {
	if oldHep := m.hepsByID[id]; oldHep != nil {
		m.decrefTier(oldHep.Tiers, iptables.TableFilter)
		m.decrefTier(oldHep.ForwardTiers, iptables.TableFilter)
		m.decrefTier(oldHep.PreDnatTiers, iptables.TableMangle)
		m.decrefTier(oldHep.UntrackedTiers, iptables.TableRaw)

		delete(m.hepsByID, id)
	}
}

func (m *policyManager) onPolicyUpdate(msg *proto.ActivePolicyUpdate) {
	id := *msg.Id
	log.WithField("id", id).Debug("Updating policy chains")
	m.policiesByID[id] = msg.Policy
	refCounts := m.policyRefCounts[id]
	for table := range refCounts {
		m.programPolicy(id, table)
	}
	m.callbacks.InvokeUpdatePolicy(id, msg.Policy)
}

func (m *policyManager) onPolicyRemove(msg *proto.ActivePolicyRemove) {
	log.WithField("id", msg.Id).Debug("Removing policy chains")
	id := *msg.Id
	if _, ok := m.policyRefCounts[id]; ok {
		log.WithField("id", id).Panic("Policy removed while still referenced")
	}
	delete(m.policiesByID, id)
	m.callbacks.InvokeRemovePolicy(id)
}

func (m *policyManager) onProfileUpdate(msg *proto.ActiveProfileUpdate) {
	log.WithField("id", msg.Id).Debug("Updating profile chains")
	chains := m.ruleRenderer.ProfileToIptablesChains(msg.Id, msg.Profile, m.ipVersion)
	m.tables[iptables.TableFilter].UpdateChains(chains)
}

func (m *policyManager) onProfileRemove(msg *proto.ActiveProfileRemove) {
	log.WithField("id", msg.Id).Debug("Removing profile chains")
	inName := rules.ProfileChainName(rules.ProfileInboundPfx, msg.Id)
	outName := rules.ProfileChainName(rules.ProfileOutboundPfx, msg.Id)
	m.tables[iptables.TableFilter].RemoveChainByName(inName)
	m.tables[iptables.TableFilter].RemoveChainByName(outName)
}

func (m *policyManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}

func (m *policyManager) programPolicy(id proto.PolicyID, table iptables.TableName) {
	policy := m.policiesByID[id]
	chains := m.ruleRenderer.PolicyToIptablesChains(&id, policy, m.ipVersion)
	m.tables[table].UpdateChains(chains)
}

func (m *policyManager) removePolicy(id proto.PolicyID, table iptables.TableName) {
	inName := rules.PolicyChainName(rules.PolicyInboundPfx, &id)
	outName := rules.PolicyChainName(rules.PolicyOutboundPfx, &id)
	m.tables[table].RemoveChainByName(inName)
	m.tables[table].RemoveChainByName(outName)
}

func (m *policyManager) increfTier(tier []*proto.TierInfo, table iptables.TableName) {
	if len(tier) > 0 {
		for _, pols := range [][]string{tier[0].IngressPolicies, tier[0].EgressPolicies} {
			for _, p := range pols {
				m.increfPolicy(proto.PolicyID{
					Tier: tier[0].Name,
					Name: p,
				}, table)
			}
		}
	}
}

func (m *policyManager) decrefTier(tier []*proto.TierInfo, table iptables.TableName) {
	if len(tier) > 0 {
		for _, pols := range [][]string{tier[0].IngressPolicies, tier[0].EgressPolicies} {
			for _, p := range pols {
				m.decrefPolicy(proto.PolicyID{
					Tier: tier[0].Name,
					Name: p,
				}, table)
			}
		}
	}
}

func (m *policyManager) increfPolicy(id proto.PolicyID, table iptables.TableName) {
	refCounts := m.policyRefCounts[id]
	if refCounts == nil {
		refCounts = make(perTableRefcounts)
	}
	if refCounts[table] == 0 {
		m.programPolicy(id, table)
	}
	refCounts[table]++
	m.policyRefCounts[id] = refCounts
}

func (m *policyManager) decrefPolicy(id proto.PolicyID, table iptables.TableName) {
	refCounts := m.policyRefCounts[id]
	refCounts[table]--
	if refCounts[table] == 0 {
		m.removePolicy(id, table)
		delete(refCounts, table)
	}
	if len(refCounts) == 0 {
		delete(m.policyRefCounts, id)
	}
}
