// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/wireguard"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/felix/proto"
)

// wireguardManager manages the dataplane resources that are used for wireguard encrypted traffic. This includes:
// -  Routing rule to route to the wireguard routing table
//
//
// It programs the relevant iptables chains (via the iptables.Table objects) along with
// per-endpoint routes (via the RouteTable).
//
// Since calculating the dispatch chains is fairly expensive, the main OnUpdate method
// simply records the pending state of each interface and defers the actual calculation
// to CompleteDeferredWork().  This is also the basis of our failure handling; updates
// that fail are left in the pending state so they can be retried later.
type wireguardManager struct {
	// Our dependencies.
	wireguardRouteTable       *wireguard.Wireguard
}

type WireguardStatusUpdateCallback func(ipVersion uint8, id interface{}, status string)

func newWireguardManager(
	wireguardRouteTable *wireguard.Wireguard,
) *wireguardManager {
	return &wireguardManager{
		wireguardRouteTable: wireguardRouteTable,
	}
}

func (m *wireguardManager) OnUpdate(protoBufMsg interface{}) {
	log.WithField("msg", protoBufMsg).Debug("Received message")
	switch msg := protoBufMsg.(type) {
	case *proto.HostMetadataUpdate:
		log.WithField("msg", msg).Debug("HostMetadataUpdate update")
		m.wireguardRouteTable.EndpointUpdate(msg.Hostname, ip.FromString(msg.Ipv4Addr))
	case *proto.HostMetadataRemove:
		log.WithField("msg", msg).Debug("HostMetadataRemove update")
		m.wireguardRouteTable.EndpointRemove(msg.Hostname)
	case *proto.RouteUpdate:
		log.WithField("msg", msg).Debug("RouteUpdate update")
		if msg.Type != proto.RouteType_WORKLOADS_NODE {
			log.Debug("RouteUpdate is not a node workload update, ignoring")
			return
		}
		cidr := ip.MustParseCIDROrIP(msg.Dst)
		if cidr != nil {
			m.wireguardRouteTable.EndpointAllowedCIDRAdd(msg.Node, cidr)
		}
	case *proto.RouteRemove:
		log.WithField("msg", msg).Debug("RouteRemove update")
		if msg.Type != proto.RouteType_WORKLOADS_NODE {
			log.Debug("RouteRemove is not a node workload update, ignoring")
			return
		}
		cidr := ip.MustParseCIDROrIP(msg.Dst)
		if cidr != nil {
			m.wireguardRouteTable.EndpointAllowedCIDRRemove(cidr)
		}
	case *proto.WireguardEndpointUpdate:
		log.WithField("msg", msg).Debug("WireguardEndpointUpdate update")
		key, err := wgtypes.ParseKey(msg.PublicKey)
		if err != nil {
			log.WithError(err).Error("error parsing wireguard public key")
		}
		m.wireguardRouteTable.EndpointWireguardUpdate(msg.Hostname, key, ip.FromString(msg.InterfaceAddr))
	case *proto.WireguardEndpointRemove:
		log.WithField("msg", msg).Debug("WireguardEndpointRemove update")
		m.wireguardRouteTable.EndpointWireguardUpdate(msg.Hostname, wgtypes.Key{}, nil)
	}
}

func (m *wireguardManager) CompleteDeferredWork() error {
	// Dataplane programming is handled through the routetable interface.
	return nil
}

func (m *wireguardManager) GetRouteTableSyncers() []routeTableSyncer {
	return []routeTableSyncer{m.wireguardRouteTable}
}
