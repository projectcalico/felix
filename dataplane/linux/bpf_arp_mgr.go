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
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/arp"
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
)

type bpfARPManager struct {
	arpMap bpf.Map

	ifaceToMac  map[int]net.HardwareAddr
	remoteNodes map[ip.V4Addr]struct{}

	neighDirty []*neighUpdate
	ifaceDirty []*ifaceUpdate

	unresolved map[int]map[ip.V4Addr]*neighUpdate
}

func newBPFARPManager(m bpf.Map) *bpfARPManager {
	return &bpfARPManager{
		arpMap:      m,
		ifaceToMac:  make(map[int]net.HardwareAddr),
		remoteNodes: make(map[ip.V4Addr]struct{}),
		unresolved:  make(map[int]map[ip.V4Addr]*neighUpdate),
	}
}

func (m *bpfARPManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *ifaceUpdate:
		m.onIfaceUpdate(msg)
	case *neighUpdate:
		m.onNeighUpdate(msg)
	case *proto.RouteUpdate:
		m.onRouteUpdate(msg)
	case *proto.RouteRemove:
		m.onRouteRemove(msg)
	}
}

func (m *bpfARPManager) onNeighUpdate(neigh *neighUpdate) {
	m.neighDirty = append(m.neighDirty, neigh)
}

func (m *bpfARPManager) onIfaceUpdate(iface *ifaceUpdate) {
	m.ifaceDirty = append(m.ifaceDirty, iface)
}

func (m *bpfARPManager) onRouteUpdate(update *proto.RouteUpdate) {
	if update.Type != proto.RouteType_REMOTE_HOST {
		return
	}

	cidr := ip.MustParseCIDROrIP(update.Dst)
	v4CIDR, ok := cidr.(ip.V4CIDR)
	if !ok {
		// FIXME IPv6
		return
	}
	if v4CIDR.Prefix() != 32 {
		log.WithField("cidr", v4CIDR).Warn("Remote node cidr not /32")
		return
	}

	ipv4 := v4CIDR.Addr().(ip.V4Addr)
	m.remoteNodes[ipv4] = struct{}{}

	log.Debugf("Resolving neighbours for a now known node IP %s", ipv4)
	for ifindex, ifaceMap := range m.unresolved {
		srcMAC, ok := m.ifaceToMac[ifindex]
		if !ok {
			continue
		}

		if n := ifaceMap[ipv4]; n != nil {
			m.updateBPFMap(srcMAC, n)
			delete(ifaceMap, ipv4)
		}
	}
	log.Debugf("Resolved neighbours for a now known node IP %s", ipv4)
}

func (m *bpfARPManager) onRouteRemove(update *proto.RouteRemove) {
	cidr := ip.MustParseCIDROrIP(update.Dst)
	v4CIDR, ok := cidr.(ip.V4CIDR)
	if !ok {
		// FIXME IPv6
		return
	}

	delete(m.remoteNodes, v4CIDR.Addr().(ip.V4Addr))
}

func (m *bpfARPManager) updateBPFMap(srcMAC net.HardwareAddr, n *neighUpdate) {
	k := arp.NewKey(n.IP, uint32(n.IfIndex))
	v := arp.NewValue(srcMAC, n.HWAddr)
	err := m.arpMap.Update(k[:], v[:])
	if err != nil {
		log.WithError(err).Warnf("Failed to update ARP for IP %s dev %d", n.IP, n.IfIndex)
	} else {
		log.Debugf("ARP updated for IP %s iface %d dstMAC %s", n.IP, n.IfIndex, n.HWAddr)
	}
}

func (m *bpfARPManager) CompleteDeferredWork() error {
	for _, i := range m.ifaceDirty {
		if i.State != ifacemonitor.StateUp {
			delete(m.ifaceToMac, i.Index)
			delete(m.unresolved, i.Index)
		} else {
			m.ifaceToMac[i.Index] = i.HardwareAddr

			log.Debugf("Resolving neighbours for a now known iface %d", i.Index)
			for _, n := range m.unresolved[i.Index] {
				m.updateBPFMap(i.HardwareAddr, n)
				var ipv4 [4]byte
				copy(ipv4[:], n.IP.To4())
				delete(m.unresolved[i.Index], ip.V4Addr(ipv4))
			}
			log.Debugf("Resolved neighbours for a now known iface %d", i.Index)
		}
	}

	for _, n := range m.neighDirty {
		ipv4 := n.IP.To4()
		if ipv4 == nil {
			log.WithField("IP", n.IP).Info("Ignoring non-IPv4 neighbour.")
			continue
		}

		var ipv4key [4]byte
		copy(ipv4key[:], ipv4)

		if _, ok := m.remoteNodes[ip.V4Addr(ipv4key)]; n.Exists && !ok {
			m.keepUnresolved(n)
			continue
		}

		var err error
		op := "remove"

		k := arp.NewKey(ipv4, uint32(n.IfIndex))

		if n.Exists {
			if srcMac, ok := m.ifaceToMac[n.IfIndex]; ok {
				v := arp.NewValue(srcMac, n.HWAddr)
				err = m.arpMap.Update(k[:], v[:])
				op = "update"
			} else {
				m.keepUnresolved(n)
			}
		} else {
			err = m.arpMap.Delete(k[:])
			m.removeUnresolved(n)
		}

		if err != nil {
			log.WithError(err).Warnf("Failed to %s ARP for IP %s dev %d", op, n.IP, n.IfIndex)
		} else {
			log.Debugf("ARP %s for IP %s iface %d dstMAC %s", op, n.IP, n.IfIndex, n.HWAddr)
		}
	}

	m.neighDirty = nil
	m.ifaceDirty = nil

	return nil
}

func (m *bpfARPManager) keepUnresolved(neigh *neighUpdate) {
	var ifaceMap map[ip.V4Addr]*neighUpdate

	if ifaceMap = m.unresolved[neigh.IfIndex]; ifaceMap == nil {
		ifaceMap = make(map[ip.V4Addr]*neighUpdate)
		m.unresolved[neigh.IfIndex] = ifaceMap
	}

	var ipv4 [4]byte
	copy(ipv4[:], neigh.IP.To4())

	ifaceMap[ip.V4Addr(ipv4)] = neigh
}

func (m *bpfARPManager) removeUnresolved(neigh *neighUpdate) {
	ifaceMap := m.unresolved[neigh.IfIndex]
	if ifaceMap == nil {
		return
	}

	var ipv4 [4]byte
	copy(ipv4[:], neigh.IP.To4())

	delete(ifaceMap, ip.V4Addr(ipv4))
}
