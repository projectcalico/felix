// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.
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

package rules

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/hashutils"
	. "github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
)

const (
	dropEncap              = true
	dontDropEncap          = false
	trafficFromTheEndpoint = "from"
	trafficToTheEndpoint   = "to"
)

func (r *DefaultRuleRenderer) WorkloadEndpointToIptablesChains(
	ifaceName string,
	epMarkMapper EndpointMarkMapper,
	adminUp bool,
	ingressPolicies []string,
	egressPolicies []string,
	profileIDs []string,
) []*Chain {
	result := []*Chain{}
	result = append(result,
		// Chain for traffic _to_ the endpoint.
		r.endpointIptablesChain(
			ingressPolicies,
			profileIDs,
			r.newWorkloadEndpointIptablesChainOptions(ifaceName, trafficToTheEndpoint, adminUp, dontDropEncap),
		),
		// Chain for traffic _from_ the endpoint.
		r.endpointIptablesChain(
			egressPolicies,
			profileIDs,
			r.newWorkloadEndpointIptablesChainOptions(ifaceName, trafficFromTheEndpoint, adminUp, dropEncap),
		),
	)

	if r.KubeIPVSSupportEnabled {
		// Chain for setting endpoint mark of an endpoint.
		result = append(result,
			r.endpointSetMarkChain(
				ifaceName,
				epMarkMapper,
				SetEndPointMarkPfx,
			),
		)
	}

	return result
}

func (r *DefaultRuleRenderer) HostEndpointToFilterChains(
	ifaceName string,
	epMarkMapper EndpointMarkMapper,
	ingressPolicyNames []string,
	egressPolicyNames []string,
	ingressForwardPolicyNames []string,
	egressForwardPolicyNames []string,
	profileIDs []string,
	defaultDropWhenNoPolicy bool,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering filter host endpoint chain.")
	result := []*Chain{}
	result = append(result,
		// Chain for output traffic _to_ the endpoint.
		r.endpointIptablesChain(
			egressPolicyNames,
			profileIDs,
			r.newHostEndpointIptablesChainOptions(ifaceName, trafficToTheEndpoint, chainTypeNormal, defaultDropWhenNoPolicy),
		),
		// Chain for input traffic _from_ the endpoint.
		r.endpointIptablesChain(
			ingressPolicyNames,
			profileIDs,
			r.newHostEndpointIptablesChainOptions(ifaceName, trafficFromTheEndpoint, chainTypeNormal, defaultDropWhenNoPolicy),
		),
		// Chain for forward traffic _to_ the endpoint.
		r.endpointIptablesChain(
			egressForwardPolicyNames,
			profileIDs,
			r.newHostEndpointIptablesChainOptions(ifaceName, trafficToTheEndpoint, chainTypeForward, defaultDropWhenNoPolicy),
		),
		// Chain for forward traffic _from_ the endpoint.
		r.endpointIptablesChain(
			ingressForwardPolicyNames,
			profileIDs,
			r.newHostEndpointIptablesChainOptions(ifaceName, trafficFromTheEndpoint, chainTypeForward, defaultDropWhenNoPolicy),
		),
	)

	if r.KubeIPVSSupportEnabled {
		// Chain for setting endpoint mark of an endpoint.
		result = append(result,
			r.endpointSetMarkChain(
				ifaceName,
				epMarkMapper,
				SetEndPointMarkPfx,
			),
		)
	}

	return result
}

func (r *DefaultRuleRenderer) HostEndpointToRawChains(
	ifaceName string,
	ingressPolicyNames []string,
	egressPolicyNames []string,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering raw (untracked) host endpoint chain.")
	return []*Chain{
		// Chain for traffic _to_ the endpoint.
		r.endpointIptablesChain(
			egressPolicyNames,
			nil,
			r.newHostEndpointIptablesChainOptions(ifaceName, trafficToTheEndpoint, chainTypeUntracked, false),
		),
		// Chain for traffic _from_ the endpoint.
		r.endpointIptablesChain(
			ingressPolicyNames,
			nil,
			r.newHostEndpointIptablesChainOptions(ifaceName, trafficFromTheEndpoint, chainTypeUntracked, true),
		),
	}
}

func (r *DefaultRuleRenderer) HostEndpointToMangleChains(
	ifaceName string,
	preDNATPolicyNames []string,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering pre-DNAT host endpoint chain.")
	return []*Chain{
		// Chain for traffic _from_ the endpoint.  Pre-DNAT policy does not apply to
		// outgoing traffic through a host endpoint.
		r.endpointIptablesChain(
			preDNATPolicyNames,
			nil,
			r.newHostEndpointIptablesChainOptions(ifaceName, trafficFromTheEndpoint, chainTypePreDNAT, false),
		),
	}
}

type endpointChainType int

const (
	chainTypeNormal endpointChainType = iota
	chainTypeUntracked
	chainTypePreDNAT
	chainTypeForward
)

func (r *DefaultRuleRenderer) endpointSetMarkChain(
	name string,
	epMarkMapper EndpointMarkMapper,
	endpointPrefix string,
) *Chain {
	rules := []Rule{}
	chainName := EndpointChainName(endpointPrefix, name)

	if endPointMark, err := epMarkMapper.GetEndpointMark(name); err == nil {
		// Set endpoint mark.
		rules = append(rules, Rule{
			Action: SetMaskedMarkAction{
				Mark: endPointMark,
				Mask: epMarkMapper.GetMask()},
		})
	}
	return &Chain{
		Name:  chainName,
		Rules: rules,
	}
}

// endpointChainOptions are options for the endpointIptablesChain method.
type endpointIptablesChainOptions struct {
	ifaceName               string
	policyPrefix            PolicyChainNamePrefix
	profilePrefix           ProfileChainNamePrefix
	endpointPrefix          string
	failsafeChainTarget     string
	chainType               endpointChainType
	interfaceIsAdminUp      bool
	allowAction             Action
	dropEncap               bool
	defaultDropWhenNoPolicy bool
}

// newWorkloadEndpointIptablesChainOptions returns a set of options to create
// a workload endpoint chain. It's used by the endpointIptablesChain method.
func (r *DefaultRuleRenderer) newWorkloadEndpointIptablesChainOptions(ifaceName string, direction string, ifaceIsAdminUp bool, dropEncap bool) *endpointIptablesChainOptions {
	var policyPrefix PolicyChainNamePrefix
	var profilePrefix ProfileChainNamePrefix
	var endpointPrefix string

	if direction == trafficToTheEndpoint {
		// Chain for input traffic _to_ the endpoint.
		policyPrefix = PolicyInboundPfx
		profilePrefix = ProfileInboundPfx
		endpointPrefix = WorkloadToEndpointPfx
	} else if direction == trafficFromTheEndpoint {
		// Chain for output traffic _from_ the endpoint.
		policyPrefix = PolicyOutboundPfx
		profilePrefix = ProfileOutboundPfx
		endpointPrefix = WorkloadFromEndpointPfx
	}

	return &endpointIptablesChainOptions{
		ifaceName,
		policyPrefix,
		profilePrefix,
		endpointPrefix,
		"", // No fail-safe chains for workloads.
		chainTypeNormal,
		ifaceIsAdminUp,
		r.filterAllowAction, // Use the configured Allow action in the rule renderer.
		dropEncap,
		true, // defaultDropWhenNoPolicy defaults to true.
	}
}

// newHostEndpointIptablesChainOptions returns a set of options to create a host
// endpoint chain. It's used by the endpointIptablesChain method.
func (r *DefaultRuleRenderer) newHostEndpointIptablesChainOptions(ifaceName string, direction string, chainType endpointChainType, defaultDropWhenNoPolicy bool) *endpointIptablesChainOptions {
	var policyPrefix PolicyChainNamePrefix
	var profilePrefix ProfileChainNamePrefix
	var endpointPrefix, failsafeChainTarget string

	// Set prefixes based off of the traffic direction.
	// Also set the fail-safe chain target if this is not the forward chain.
	if direction == trafficFromTheEndpoint {
		// Chain for input traffic _from_ the endpoint.
		policyPrefix = PolicyInboundPfx
		profilePrefix = ProfileInboundPfx

		if chainType == chainTypeForward {
			endpointPrefix = HostFromEndpointForwardPfx
		} else {
			endpointPrefix = HostFromEndpointPfx
			failsafeChainTarget = ChainFailsafeIn
		}

	} else if direction == trafficToTheEndpoint {
		// Chain for input traffic _to the endpoint.
		policyPrefix = PolicyOutboundPfx
		profilePrefix = ProfileOutboundPfx

		if chainType == chainTypeForward {
			endpointPrefix = HostToEndpointForwardPfx
		} else {
			endpointPrefix = HostToEndpointPfx
			failsafeChainTarget = ChainFailsafeOut
		}
	}

	allowAction := r.filterAllowAction
	if chainType == chainTypeUntracked {
		allowAction = AcceptAction{}
	}
	if chainType == chainTypePreDNAT {
		allowAction = r.mangleAllowAction
	}

	return &endpointIptablesChainOptions{
		ifaceName,
		policyPrefix,
		profilePrefix,
		endpointPrefix,
		failsafeChainTarget,
		chainType,
		true, // interfaceIsAdminUp defaults to true.
		allowAction,
		dontDropEncap,
		defaultDropWhenNoPolicy, // defaultDropWhenNoPolicy
	}
}

func (r *DefaultRuleRenderer) endpointIptablesChain(
	policyNames []string,
	profileIds []string,
	options *endpointIptablesChainOptions,
) *Chain {
	rules := []Rule{}
	chainName := EndpointChainName(options.endpointPrefix, options.ifaceName)

	if !options.interfaceIsAdminUp {
		// Endpoint is admin-down, drop all traffic to/from it.
		rules = append(rules, Rule{
			Match:   Match(),
			Action:  DropAction{},
			Comment: []string{"Endpoint admin disabled"},
		})
		return &Chain{
			Name:  chainName,
			Rules: rules,
		}
	}

	if options.chainType != chainTypeUntracked {
		// Tracked chain: install conntrack rules, which implement our stateful connections.
		// This allows return traffic associated with a previously-permitted request.
		rules = r.appendConntrackRules(rules, options.allowAction)
	}

	// First set up failsafes.
	if options.failsafeChainTarget != "" {
		rules = append(rules, Rule{
			Action: JumpAction{Target: options.failsafeChainTarget},
		})
	}

	// Start by ensuring that the accept mark bit is clear, policies set that bit to indicate
	// that they accepted the packet.
	rules = append(rules, Rule{
		Action: ClearMarkAction{
			Mark: r.IptablesMarkAccept,
		},
	})

	if options.dropEncap {
		rules = append(rules, Rule{
			Match: Match().ProtocolNum(ProtoUDP).
				DestPorts(uint16(r.Config.VXLANPort)),
			Action:  DropAction{},
			Comment: []string{"Drop VXLAN encapped packets originating in pods"},
		})
		rules = append(rules, Rule{
			Match:   Match().ProtocolNum(ProtoIPIP),
			Action:  DropAction{},
			Comment: []string{"Drop IPinIP encapped packets originating in pods"},
		})
	}

	if len(policyNames) > 0 {
		// Clear the "pass" mark.  If a policy sets that mark, we'll skip the rest of the policies and
		// continue processing the profiles, if there are any.
		rules = append(rules, Rule{
			Comment: []string{"Start of policies"},
			Action: ClearMarkAction{
				Mark: r.IptablesMarkPass,
			},
		})

		// Then, jump to each policy in turn.
		for _, polID := range policyNames {
			polChainName := PolicyChainName(
				options.policyPrefix,
				&proto.PolicyID{Name: polID},
			)

			// If a previous policy didn't set the "pass" mark, jump to the policy.
			rules = append(rules, Rule{
				Match:  Match().MarkClear(r.IptablesMarkPass),
				Action: JumpAction{Target: polChainName},
			})
			// If policy marked packet as accepted, it returns, setting the accept
			// mark bit.
			if options.chainType == chainTypeUntracked {
				// For an untracked policy, map allow to "NOTRACK and ALLOW".
				rules = append(rules, Rule{
					Match:  Match().MarkSingleBitSet(r.IptablesMarkAccept),
					Action: NoTrackAction{},
				})
			}
			// If accept bit is set, return from this chain.  We don't immediately
			// accept because there may be other policy still to apply.
			rules = append(rules, Rule{
				Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
				Action:  ReturnAction{},
				Comment: []string{"Return if policy accepted"},
			})
		}

		if options.chainType == chainTypeNormal || options.chainType == chainTypeForward {
			// When rendering normal and forward rules, if no policy marked the packet as "pass", drop the
			// packet.
			//
			// For untracked and pre-DNAT rules, we don't do that because there may be
			// normal rules still to be applied to the packet in the filter table.
			rules = append(rules, Rule{
				Match:   Match().MarkClear(r.IptablesMarkPass),
				Action:  DropAction{},
				Comment: []string{"Drop if no policies passed packet"},
			})
		}

	} else if options.chainType == chainTypeForward {
		// Forwarded traffic is allowed when there are no policies with
		// applyOnForward that apply to this endpoint (and in this direction).
		rules = append(rules, Rule{
			Action:  SetMarkAction{Mark: r.IptablesMarkAccept},
			Comment: []string{"Allow forwarded traffic by default"},
		})
		rules = append(rules, Rule{
			Action:  ReturnAction{},
			Comment: []string{"Return for accepted forward traffic"},
		})
	}

	if options.chainType == chainTypeNormal {
		// Then, jump to each profile in turn.
		for _, profileID := range profileIds {
			profChainName := ProfileChainName(options.profilePrefix, &proto.ProfileID{Name: profileID})
			rules = append(rules,
				Rule{Action: JumpAction{Target: profChainName}},
				// If policy marked packet as accepted, it returns, setting the
				// accept mark bit.  If that is set, return from this chain.
				Rule{
					Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
					Action:  ReturnAction{},
					Comment: []string{"Return if profile accepted"},
				})
		}

		// When rendering normal rules, except for the wildcard HEP, drop the packet if no
		// policy or profile allowed it.
		//
		// For untracked and pre-DNAT rules, we don't do that because there may be tracked
		// rules still to be applied to the packet in the filter table.
		//
		// For the wildcard HEP, we allow when there is no policy, because wildcard HEPs
		// were previously implemented only for pre-DNAT policy and so had no interaction
		// with normal policy.
		if options.defaultDropWhenNoPolicy {
			rules = append(rules, Rule{
				Match:   Match(),
				Action:  DropAction{},
				Comment: []string{"Drop if no profiles matched"},
			})
		} else {
			rules = append(rules, Rule{
				Action:  SetMarkAction{Mark: r.IptablesMarkAccept},
				Comment: []string{"Allow traffic by default"},
			})
			rules = append(rules, Rule{
				Action:  ReturnAction{},
				Comment: []string{"Return for allowed traffic"},
			})
		}
	}

	return &Chain{
		Name:  chainName,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) appendConntrackRules(rules []Rule, allowAction Action) []Rule {
	// Allow return packets for established connections.
	if allowAction != (AcceptAction{}) {
		// If we've been asked to return instead of accept the packet immediately,
		// make sure we flag the packet as allowed.
		rules = append(rules,
			Rule{
				Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
				Action: SetMarkAction{Mark: r.IptablesMarkAccept},
			},
		)
	}
	rules = append(rules,
		Rule{
			Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
			Action: allowAction,
		},
	)
	if !r.Config.DisableConntrackInvalid {
		// Drop packets that aren't either a valid handshake or part of an established
		// connection.
		rules = append(rules, Rule{
			Match:  Match().ConntrackState("INVALID"),
			Action: DropAction{},
		})
	}
	return rules
}

func EndpointChainName(prefix string, ifaceName string) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		ifaceName,
		MaxChainNameLength,
	)
}
