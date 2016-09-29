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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/datastructures/ip"
	"github.com/projectcalico/felix/go/datastructures/multidict"
	"github.com/projectcalico/felix/go/datastructures/set"
	"github.com/projectcalico/felix/go/felix/config"
	"github.com/projectcalico/felix/go/felix/endpoint"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/tigera/libcalico-go/lib/backend/model"
	"github.com/tigera/libcalico-go/lib/net"
	"github.com/tigera/libcalico-go/lib/numorstring"
	"strconv"
	"strings"
)

type EventHandler func(message interface{})

type configInterface interface {
	UpdateFrom(map[string]string, config.Source) (changed bool, err error)
	RawValues() map[string]string
}

type EventBuffer struct {
	config        configInterface
	knownIPSets   set.Set
	ipSetsAdded   set.Set
	ipSetsRemoved set.Set
	ipsAdded      multidict.StringToIface
	ipsRemoved    multidict.StringToIface

	pendingUpdates []interface{}

	Callback EventHandler
}

func NewEventBuffer(conf configInterface) *EventBuffer {
	buf := &EventBuffer{
		config:        conf,
		ipSetsAdded:   set.New(),
		ipSetsRemoved: set.New(),
		ipsAdded:      multidict.NewStringToIface(),
		ipsRemoved:    multidict.NewStringToIface(),
		knownIPSets:   set.New(),
	}
	return buf
}

func (buf *EventBuffer) OnIPSetAdded(setID string) {
	log.Debugf("IP set %v now active", setID)
	if buf.knownIPSets.Contains(setID) && !buf.ipSetsRemoved.Contains(setID) {
		log.Fatalf("OnIPSetAdded called for existing IP set")
	}
	buf.ipSetsAdded.Add(setID)
	buf.ipSetsRemoved.Discard(setID)
	buf.ipsAdded.DiscardKey(setID)
	buf.ipsRemoved.DiscardKey(setID)
}

func (buf *EventBuffer) OnIPSetRemoved(setID string) {
	log.Debugf("IP set %v no longer active", setID)
	if !buf.knownIPSets.Contains(setID) && !buf.ipSetsAdded.Contains(setID) {
		log.Fatalf("IPSetRemoved called for unknown IP set: %v", setID)
	}
	if buf.knownIPSets.Contains(setID) {
		buf.ipSetsRemoved.Add(setID)
	}
	buf.ipSetsAdded.Discard(setID)
	buf.ipsAdded.DiscardKey(setID)
	buf.ipsRemoved.DiscardKey(setID)
}

func (buf *EventBuffer) OnIPAdded(setID string, ip ip.Addr) {
	log.Debugf("IP set %v now contains %v", setID, ip)
	if !buf.knownIPSets.Contains(setID) && !buf.ipSetsAdded.Contains(setID) {
		log.Fatalf("IP added to unknown IP set: %v", setID)
	}
	if buf.ipsRemoved.Contains(setID, ip) {
		buf.ipsRemoved.Discard(setID, ip)
	} else {
		buf.ipsAdded.Put(setID, ip)
	}
}

func (buf *EventBuffer) OnIPRemoved(setID string, ip ip.Addr) {
	log.Debugf("IP set %v no longer contains %v", setID, ip)
	if !buf.knownIPSets.Contains(setID) && !buf.ipSetsAdded.Contains(setID) {
		log.Fatalf("IP removed from unknown IP set: %v", setID)
	}
	if buf.ipsAdded.Contains(setID, ip) {
		buf.ipsAdded.Discard(setID, ip)
	} else {
		buf.ipsRemoved.Put(setID, ip)
	}
}

func (buf *EventBuffer) Flush() {
	buf.ipSetsRemoved.Iter(func(item interface{}) (err error) {
		setID := item.(string)
		log.Debugf("Flushing IP set remove: %v", setID)
		buf.Callback(&proto.IPSetRemove{
			Id: setID,
		})
		buf.ipsRemoved.DiscardKey(setID)
		buf.ipsAdded.DiscardKey(setID)
		buf.ipSetsRemoved.Discard(item)
		buf.knownIPSets.Discard(item)
		return
	})
	log.Debugf("Done flushing IP set removes")
	buf.ipSetsAdded.Iter(func(item interface{}) (err error) {
		setID := item.(string)
		log.Debugf("Flushing IP set added: %v", setID)
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
		buf.knownIPSets.Add(item)
		return
	})
	log.Debugf("Done flushing IP set adds")
	buf.ipsRemoved.IterKeys(buf.flushAddsOrRemoves)
	log.Debugf("Done flushing IP address removes")
	buf.ipsAdded.IterKeys(buf.flushAddsOrRemoves)
	log.Debugf("Done flushing IP address adds")

	log.Debugf("Flushing %v pending updates", len(buf.pendingUpdates))
	for _, update := range buf.pendingUpdates {
		buf.Callback(update)
	}
	log.Debugf("Done flushing %v pending updates", len(buf.pendingUpdates))
	buf.pendingUpdates = make([]interface{}, 0)
}

func (buf *EventBuffer) flushAddsOrRemoves(setID string) {
	log.Debugf("Flushing IP set deltas: %v", setID)
	deltaUpdate := proto.IPSetDeltaUpdate{
		Id: setID,
	}
	buf.ipsAdded.Iter(setID, func(item interface{}) {
		ip := item.(ip.Addr).String()
		deltaUpdate.AddedMembers = append(deltaUpdate.AddedMembers, ip)
	})
	buf.ipsRemoved.Iter(setID, func(item interface{}) {
		ip := item.(ip.Addr).String()
		deltaUpdate.RemovedMembers = append(deltaUpdate.RemovedMembers, ip)
	})
	buf.ipsAdded.DiscardKey(setID)
	buf.ipsRemoved.DiscardKey(setID)
	buf.Callback(&deltaUpdate)
}

func (buf *EventBuffer) OnConfigUpdate(globalConfig, hostConfig map[string]string) {
	logCxt := log.WithFields(log.Fields{
		"global": globalConfig,
		"host":   hostConfig,
	})
	logCxt.Info("Possible config update.")
	globalChanged, err := buf.config.UpdateFrom(globalConfig, config.DatastoreGlobal)
	if err != nil {
		logCxt.WithError(err).Fatal("Failed to parse config update")
	}
	hostChanged, err := buf.config.UpdateFrom(hostConfig, config.DatastorePerHost)
	if err != nil {
		logCxt.WithError(err).Fatal("Failed to parse config update")
	}
	if globalChanged || hostChanged {
		rawConfig := buf.config.RawValues()
		log.WithField("merged", rawConfig).Warn("Config changed. Sending ConfigUpdate message.")
		buf.pendingUpdates = append(buf.pendingUpdates, &proto.ConfigUpdate{
			Config: rawConfig,
		})
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
	log.Debugf("Endpoint/tier update: %v", endpointKey)
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

func (buf *EventBuffer) OnHostIPUpdate(hostname string, ip *net.IP) {
	buf.pendingUpdates = append(buf.pendingUpdates,
		&proto.HostMetadataUpdate{
			Hostname: hostname,
			Ipv4Addr: ip.IP.String(),
		})
}

func (buf *EventBuffer) OnHostIPRemove(hostname string) {
	buf.pendingUpdates = append(buf.pendingUpdates,
		&proto.HostMetadataRemove{
			Hostname: hostname,
		})
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
		Action: in.Action,

		IpVersion: convertIPVersion(in.IPVersion),

		Protocol: convertProtocol(in.Protocol),

		SrcNet:      convertNet(in.SrcNet),
		SrcPorts:    convertPorts(in.SrcPorts),
		DstNet:      convertNet(in.DstNet),
		DstPorts:    convertPorts(in.DstPorts),
		SrcIpSetIds: in.SrcIPSetIDs,
		DstIpSetIds: in.DstIPSetIDs,
		Icmp:        convertIcmp(in.ICMPType, in.ICMPCode),

		NotProtocol:    convertProtocol(in.NotProtocol),
		NotSrcNet:      convertNet(in.NotSrcNet),
		NotSrcPorts:    convertPorts(in.NotSrcPorts),
		NotDstNet:      convertNet(in.NotDstNet),
		NotDstPorts:    convertPorts(in.NotDstPorts),
		NotSrcIpSetIds: in.NotSrcIPSetIDs,
		NotDstIpSetIds: in.NotDstIPSetIDs,
		NotIcmp:        convertIcmp(in.NotICMPType, in.NotICMPCode),

		LogPrefix: in.LogPrefix,
	}

	return out
}

func convertIPVersion(in *int) proto.IPVersion {
	if in == nil {
		return proto.IPVersion_ANY
	}
	switch *in {
	case 4:
		return proto.IPVersion_IPV4
	case 6:
		return proto.IPVersion_IPV6
	}
	return proto.IPVersion_ANY
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

func convertIcmp(icmpType, icmpCode *int) (out *proto.ICMPMatch) {
	if icmpType == nil {
		return
	}
	out = &proto.ICMPMatch{
		Type: int32(*icmpType),
	}
	if icmpCode != nil {
		out.Code = int32(*icmpCode)
	}
	return
}
