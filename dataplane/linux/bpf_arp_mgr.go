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
)

type bpfARPManager struct {
	arpMap bpf.Map

	ifaceToMac map[int]net.HardwareAddr

	neighDirty []*neighUpdate
	ifaceDirty []*ifaceUpdate
}

func newBPFARPManager(m bpf.Map) *bpfARPManager {
	return &bpfARPManager{
		arpMap:     m,
		ifaceToMac: make(map[int]net.HardwareAddr),
	}
}

func (m *bpfARPManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *ifaceUpdate:
		m.onIfaceUpdate(msg)
	case *neighUpdate:
		m.onNeighUpdate(msg)
	}
}

func (m *bpfARPManager) onNeighUpdate(neigh *neighUpdate) {
	m.neighDirty = append(m.neighDirty, neigh)
}

func (m *bpfARPManager) onIfaceUpdate(iface *ifaceUpdate) {
	m.ifaceDirty = append(m.ifaceDirty, iface)
}

func (m *bpfARPManager) CompleteDeferredWork() error {
	for _, i := range m.ifaceDirty {
		if i.State != ifacemonitor.StateUp {
			delete(m.ifaceToMac, i.Index)
		} else {
			m.ifaceToMac[i.Index] = i.HardwareAddr
		}
	}

	for _, n := range m.neighDirty {
		ip := n.IP.To4()
		if ip == nil {
			log.WithField("IP", n.IP).Info("Ignoring non-IPv4 neighbour.")
			continue
		}

		var err error
		op := "remove"

		k := arp.NewKey(ip, uint32(n.IfIndex))
		if n.Exists {
			if srcMac, ok := m.ifaceToMac[n.IfIndex]; ok {
				v := arp.NewValue(srcMac, n.HWAddr)
				err = m.arpMap.Update(k[:], v[:])
				op = "update"
			} else {
				err = m.arpMap.Delete(k[:])
			}
		} else {
			err = m.arpMap.Delete(k[:])
		}

		if err != nil {
			log.WithError(err).Warnf("Failed to %s ARP for IP dev %d%s", op, n.IP, n.Ifindex)
		} else {
			log.Debugf("ARP %s for IP %s iface %d dstMAC %s", op, n.IP, n.IfIndex, n.HWAddr)
		}
	}

	m.neighDirty = nil
	m.ifaceDirty = nil

	return nil
}
