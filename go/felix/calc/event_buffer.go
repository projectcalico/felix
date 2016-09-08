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

package calc

import (
	"github.com/golang/glog"
	"github.com/projectcalico/calico/go/datastructures/ip"
	"github.com/projectcalico/calico/go/datastructures/multidict"
	"github.com/projectcalico/calico/go/datastructures/set"
	"github.com/projectcalico/calico/go/felix/config"
	"github.com/projectcalico/calico/go/felix/endpoint"
	"github.com/projectcalico/calico/go/felix/proto"
	"github.com/tigera/libcalico-go/lib/backend/model"
	"github.com/tigera/libcalico-go/lib/net"
	"github.com/tigera/libcalico-go/lib/numorstring"
	"strconv"
	"strings"
)

type EventHandler func(message interface{})

type configInterface interface {
	UpdateFrom(map[string]string, config.Source) (changed bool, err error)
}

type EventBuffer struct {
	config         configInterface
	ipSetsAdded    set.Set
	ipSetsRemoved  set.Set
	ipsAdded       multidict.StringToIface
	ipsRemoved     multidict.StringToIface

	pendingUpdates []interface{}

	Callback       EventHandler
}

func NewEventBuffer(conf configInterface) *EventBuffer {
	buf := &EventBuffer{
		config:        conf,
		ipSetsAdded:   set.New(),
		ipSetsRemoved: set.New(),
		ipsAdded:      multidict.NewStringToIface(),
		ipsRemoved:    multidict.NewStringToIface(),
	}
	return buf
}

func (buf *EventBuffer) OnIPSetAdded(setID string) {
	glog.V(3).Infof("IP set %v now active", setID)
	buf.ipSetsAdded.Add(setID)
	buf.ipSetsRemoved.Discard(setID)
}

func (buf *EventBuffer) OnIPSetRemoved(setID string) {
	glog.V(3).Infof("IP set %v no longer active", setID)
	buf.ipSetsAdded.Discard(setID)
	buf.ipSetsRemoved.Add(setID)
}

func (buf *EventBuffer) OnIPAdded(setID string, ip ip.Addr) {
	glog.V(4).Infof("IP set %v now contains %v", setID, ip)
	buf.ipsAdded.Put(setID, ip)
	buf.ipsRemoved.Discard(setID, ip)
}

func (buf *EventBuffer) OnIPRemoved(setID string, ip ip.Addr) {
	glog.V(4).Infof("IP set %v no longer contains %v", setID, ip)
	buf.ipsAdded.Discard(setID, ip)
	buf.ipsRemoved.Put(setID, ip)
}

func (buf *EventBuffer) Flush() {
	buf.ipSetsRemoved.Iter(func(item interface{}) (err error) {
		setID := item.(string)
		glog.V(3).Infof("Flushing IP set remove: %v", setID)
		buf.Callback(&proto.IPSetRemove{
			Id: setID,
		})
		buf.ipsRemoved.DiscardKey(setID)
		buf.ipsAdded.DiscardKey(setID)
		buf.ipSetsRemoved.Discard(item)
		return
	})
	glog.V(3).Infof("Done flushing IP set removes")
	buf.ipSetsAdded.Iter(func(item interface{}) (err error) {
		setID := item.(string)
		glog.V(3).Infof("Flushing IP set added: %v", setID)
		members := make([]string, 0)
		buf.ipsAdded.Iter(setID, func(value interface{}) {
			members = append(members, value.(ip.Addr).String())
		})
		buf.ipsAdded.DiscardKey(setID)
		buf.Callback(&proto.IPSetUpdate{
			Id:      setID,
			Members: members,
		})
		buf.ipSetsAdded.Discard(item)
		return
	})
	glog.V(3).Infof("Done flushing IP set adds")
	buf.ipsRemoved.IterKeys(buf.flushAddsOrRemoves)
	glog.V(3).Infof("Done flushing IP address removes")
	buf.ipsAdded.IterKeys(buf.flushAddsOrRemoves)
	glog.V(3).Infof("Done flushing IP address adds")

	glog.V(3).Infof("Flushing %v pending updates", len(buf.pendingUpdates))
	for _, update := range buf.pendingUpdates {
		buf.Callback(update)
	}
	glog.V(3).Infof("Done flushing %v pending updates", len(buf.pendingUpdates))
	buf.pendingUpdates = make([]interface{}, 0)
}

func (buf *EventBuffer) flushAddsOrRemoves(setID string) {
	glog.V(3).Infof("Flushing IP set deltas: %v", setID)
	deltaUpdate := proto.IPSetDeltaUpdate{
		Id: setID,
	}
	buf.ipsAdded.Iter(setID, func(item interface{}) {
		ip := item.(ip.Addr).String()
		deltaUpdate.AddedMembers = append(deltaUpdate.AddedMembers, ip)
	})
	buf.ipsRemoved.Iter(setID, func(item interface{}) {
		ip := item.(ip.Addr).String()
		deltaUpdate.AddedMembers = append(deltaUpdate.AddedMembers, ip)
	})
	buf.ipsAdded.DiscardKey(setID)
	buf.ipsRemoved.DiscardKey(setID)
	buf.Callback(&deltaUpdate)
}

func (buf *EventBuffer) OnConfigUpdate(globalConfig, hostConfig map[string]string) {
	glog.V(3).Infof("Config update: %v, %v", globalConfig, hostConfig)
	changed, err := buf.config.UpdateFrom(globalConfig, config.DatastoreGlobal)
	if err != nil {
		glog.Fatalf("Failed to parse config update: %v", err)
	}
	if changed {
		glog.Fatalf("Config changed, need to restart.")
	}
	changed, err = buf.config.UpdateFrom(hostConfig, config.DatastorePerHost)
	if err != nil {
		glog.Fatalf("Failed to parse config update: %v", err)
	}
	if changed {
		glog.Fatalf("Config changed, need to restart.")
	}
}

func (buf *EventBuffer) OnPolicyActive(key model.PolicyKey, rules *ParsedRules) {
	buf.pendingUpdates = append(buf.pendingUpdates, &proto.ActivePolicyUpdate{
		Id: &proto.PolicyID{
			Tier: key.Tier,
			Name: key.Name,
		},
		Policy: &proto.Policy{
			InboundRules:  convertRules(rules.InboundRules),
			OutboundRules: convertRules(rules.OutboundRules),
		},
	})
}

func (buf *EventBuffer) OnPolicyInactive(key model.PolicyKey) {
	buf.pendingUpdates = append(buf.pendingUpdates, &proto.ActivePolicyRemove{
		Id: &proto.PolicyID{
			Tier: key.Tier,
			Name: key.Name,
		},
	})
}

func (buf *EventBuffer) OnProfileActive(key model.ProfileRulesKey, rules *ParsedRules) {
	buf.pendingUpdates = append(buf.pendingUpdates, &proto.ActiveProfileUpdate{
		Id: &proto.ProfileID{
			Name: key.Name,
		},
		Profile: &proto.Profile{
			InboundRules:  convertRules(rules.InboundRules),
			OutboundRules: convertRules(rules.OutboundRules),
		},
	})
}

func (buf *EventBuffer) OnProfileInactive(key model.ProfileRulesKey) {
	buf.pendingUpdates = append(buf.pendingUpdates, &proto.ActiveProfileRemove{
		Id: &proto.ProfileID{
			Name: key.Name,
		},
	})
}

func (buf *EventBuffer) OnEndpointTierUpdate(endpointKey model.Key,
	endpoint interface{},
	filteredTiers []endpoint.TierInfo) {
	glog.V(3).Infof("Endpoint/tier update: %v", endpointKey)
	tiers := convertBackendTierInfo(filteredTiers)
	switch key := endpointKey.(type) {
	case model.WorkloadEndpointKey:
		if endpoint == nil {
			buf.pendingUpdates = append(buf.pendingUpdates,
				&proto.WorkloadEndpointRemove{
					Id: &proto.WorkloadEndpointID{
						OrchestratorId: key.OrchestratorID,
						WorkloadId:     key.WorkloadID,
						EndpointId:     key.EndpointID,
					},
				})
			return
		}
		ep := endpoint.(*model.WorkloadEndpoint)
		buf.pendingUpdates = append(buf.pendingUpdates,
			&proto.WorkloadEndpointUpdate{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: key.OrchestratorID,
					WorkloadId:     key.WorkloadID,
					EndpointId:     key.EndpointID,
				},

				Endpoint: &proto.WorkloadEndpoint{
					State:      ep.State,
					Name:       ep.Name,
					Mac:        ep.Mac.String(),
					ProfileIds: ep.ProfileIDs,
					Ipv4Nets:   netsToStrings(ep.IPv4Nets),
					Ipv6Nets:   netsToStrings(ep.IPv6Nets),
					Tiers:      tiers,
				},
			})
	case model.HostEndpointKey:
		if endpoint == nil {
			buf.pendingUpdates = append(buf.pendingUpdates,
				&proto.HostEndpointRemove{
					Id: &proto.HostEndpointID{
						EndpointId: key.EndpointID,
					},
				})
			return
		}
		ep := endpoint.(*model.HostEndpoint)
		buf.pendingUpdates = append(buf.pendingUpdates,
			&proto.HostEndpointUpdate{
				Id: &proto.HostEndpointID{
					EndpointId: key.EndpointID,
				},
				Endpoint: &proto.HostEndpoint{
					Name:              ep.Name,
					ExpectedIpv4Addrs: ipsToStrings(ep.ExpectedIPv4Addrs),
					ExpectedIpv6Addrs: ipsToStrings(ep.ExpectedIPv6Addrs),
					ProfileIds:        ep.ProfileIDs,
					Tiers:             tiers,
				},
			})
	}
}

func convertBackendTierInfo(filteredTiers []endpoint.TierInfo) []*proto.TierInfo {
	tiers := make([]*proto.TierInfo, len(filteredTiers))
	if len(filteredTiers) > 0 {
		for ii, ti := range filteredTiers {
			pols := make([]string, len(ti.OrderedPolicies))
			for jj, pol := range ti.OrderedPolicies {
				pols[jj] = pol.Key.Name
			}
			tiers[ii] = &proto.TierInfo{ti.Name, pols}
		}
	}
	return tiers
}

func netsToStrings(nets []net.IPNet) []string {
	strings := make([]string, len(nets))
	for ii, ip := range nets {
		strings[ii] = ip.String()
	}
	return strings
}

func ipsToStrings(ips []net.IP) []string {
	strings := make([]string, len(ips))
	for ii, ip := range ips {
		strings[ii] = ip.String()
	}
	return strings
}

func convertRules(in []*ParsedRule) (out []*proto.Rule) {
	out = make([]*proto.Rule, len(in))
	for ii, inRule := range in {
		out[ii] = convertRule(inRule)
	}
	return
}

func convertRule(in *ParsedRule) *proto.Rule {
	out := &proto.Rule{
		Protocol:    convertProtocol(in.Protocol),
		NotProtocol: convertProtocol(in.NotProtocol),

		SrcNet:      convertNet(in.SrcNet),
		SrcPorts:    convertPorts(in.SrcPorts),
		DstNet:      convertNet(in.DstNet),
		DstPorts:    convertPorts(in.DstPorts),
		SrcIpSetIds: in.SrcIPSetIDs,
		DstIpSetIds: in.DstIPSetIDs,
		IcmpType:    convertIntPointer(in.ICMPType),
		IcmpCode:    convertIntPointer(in.ICMPCode),

		NotSrcNet:      convertNet(in.NotSrcNet),
		NotSrcPorts:    convertPorts(in.NotSrcPorts),
		NotDstNet:      convertNet(in.NotDstNet),
		NotDstPorts:    convertPorts(in.NotDstPorts),
		NotSrcIpSetIds: in.NotSrcIPSetIDs,
		NotDstIpSetIds: in.NotDstIPSetIDs,
		NotIcmpType:    convertIntPointer(in.ICMPType),
		NotIcmpCode:    convertIntPointer(in.ICMPCode),

		LogPrefix: in.LogPrefix,
	}

	return out
}

func convertProtocol(in *numorstring.Protocol) (out *proto.Protocol) {
	if in != nil {
		if in.Type == numorstring.NumOrStringNum {
			out = &proto.Protocol{
				NumberOrName: &proto.Protocol_Number{in.NumVal},
			}
		} else {
			out = &proto.Protocol{
				NumberOrName: &proto.Protocol_Name{in.StrVal},
			}
		}
	}
	return
}

func convertNet(in *net.IPNet) (out string) {
	if in != nil {
		out = in.String()
	}
	return
}

func convertPorts(in []numorstring.Port) (out []*proto.PortRange) {
	out = make([]*proto.PortRange, len(in))
	for ii, port := range in {
		out[ii] = convertPort(port)
	}
	return
}

func convertPort(in numorstring.Port) (out *proto.PortRange) {
	out = &proto.PortRange{}
	if in.Type == numorstring.NumOrStringNum {
		out.First = in.NumVal
		out.Last = in.NumVal
	} else {
		parts := strings.Split(in.StrVal, ":")
		if len(parts) == 1 {
			// BUG(smc) Handle failure to parse
			port, _ := strconv.Atoi(parts[0])
			out.First = int32(port)
			out.Last = int32(port)
		} else {
			first, _ := strconv.Atoi(parts[0])
			last, _ := strconv.Atoi(parts[1])
			out.First = int32(first)
			out.Last = int32(last)
		}
	}
	return
}

func convertIntPointer(in *int) (out int32) {
	if in != nil {
		out = int32(*in)
	}
	return
}
