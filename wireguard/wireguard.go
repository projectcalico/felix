// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.
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

package wireguard

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	netlinkshim "github.com/projectcalico/felix/netlink"
	"github.com/projectcalico/felix/routetable"
	timeshim "github.com/projectcalico/felix/time"
	"github.com/projectcalico/libcalico-go/lib/set"
)

const (
	// The number of netlink connection retries before we either panic (for standard link operations) or back-off (for
	// wireguard operations).
	maxConnFailures = 3

	// For wireguard client connections we back off retries and only try to actually connect once every
	// <wireguardClientRetryInterval> requests.
	wireguardClientRetryInterval = 10
)

var (
	ErrUpdateFailed       = errors.New("netlink update operation failed")
	ErrNotSupported       = errors.New("wireguard not supported")

	// Internal types
	errWrongInterfaceType = errors.New("incorrect interface type for wireguard")
	zeroKey               = wgtypes.Key{}
)

const (
	wireguardType = "wireguard"
)

type noOpConnTrack struct{}

func (*noOpConnTrack) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {}

type nodeData struct {
	ipv4EndpointAddr      ip.Addr
	ipv4InterfaceAddr     ip.Addr
	publicKey             wgtypes.Key
	cidrs                 set.Set
	programmedInWireguard bool
	routingToWireguard    bool
}

func newNodeData() *nodeData {
	return &nodeData{
		cidrs: set.New(),
	}
}

func (n *nodeData) allowedCidrsForWireguard() []net.IPNet {
	cidrs := make([]net.IPNet, 0, n.cidrs.Len())
	n.cidrs.Iter(func(item interface{}) error {
		cidrs = append(cidrs, item.(ip.CIDR).ToIPNet())
		return nil
	})
	return cidrs
}

type nodeUpdateData struct {
	deleted             bool
	ipv4EndpointAddr    *ip.Addr
	ipv4InterfaceAddr   *ip.Addr
	publicKey           *wgtypes.Key
	allowedCidrsAdded   set.Set
	allowedCidrsDeleted set.Set
}

func newNodeUpdateData() *nodeUpdateData {
	return &nodeUpdateData{
		allowedCidrsDeleted: set.New(),
		allowedCidrsAdded:   set.New(),
	}
}

type Wireguard struct {
	// Wireguard configuration (this will not change without a restart).
	hostname string
	config   *Config
	logCxt   *logrus.Entry

	// Clients, client factories and testing shims.
	newWireguardNetlink                  func() (netlinkshim.Netlink, error)
	newWireguardDevice                   func() (netlinkshim.Wireguard, error)
	cachedNetlinkClient                  netlinkshim.Netlink
	cachedWireguard                      netlinkshim.Wireguard
	numConsistentLinkClientFailures      int
	numConsistentWireguardClientFailures int
	time                                 timeshim.Time

	// State information.
	inSyncWireguard     bool
	inSyncLink          bool
	inSyncInterfaceAddr bool
	inSyncKey           bool
	inSyncRouteRule     bool
	ifaceUp             bool
	ourPublicKey        *wgtypes.Key

	// Current configuration
	// - all nodeData information
	// - mapping between CIDRs and nodeData
	// - mapping between public key and nodes - this does not include the "zero" key.
	nodes                map[string]*nodeData
	cidrToNodeName       map[ip.CIDR]string
	publicKeyToNodeNames map[wgtypes.Key]set.Set

	// Pending updates
	nodeUpdates           map[string]*nodeUpdateData
	cidrToNodeNameUpdates map[ip.CIDR]string

	// Wireguard routing table
	routetable *routetable.RouteTable

	// Callback function used to notify of public key updates for the local nodeData
	statusCallback func(publicKey wgtypes.Key) error
}

func New(
	hostname string,
	config *Config,
	netlinkTimeout time.Duration,
	deviceRouteProtocol int,
	statusCallback func(publicKey wgtypes.Key) error,
) *Wireguard {
	return NewWithShims(
		hostname,
		config,
		netlinkshim.NewRealNetlink,
		netlinkshim.NewRealNetlink,
		netlinkshim.NewRealWireguard,
		netlinkTimeout,
		timeshim.NewRealTime(),
		deviceRouteProtocol,
		statusCallback,
	)
}

// NewWithShims is a test constructor, which allows linkClient, arp and time to be replaced by shims.
func NewWithShims(
	hostname string,
	config *Config,
	newRoutetableNetlink func() (netlinkshim.Netlink, error),
	newWireguardNetlink func() (netlinkshim.Netlink, error),
	newWireguardDevice func() (netlinkshim.Wireguard, error),
	netlinkTimeout time.Duration,
	timeShim timeshim.Time,
	deviceRouteProtocol int,
	statusCallback func(publicKey wgtypes.Key) error,
) *Wireguard {
	// Create routetable. We provide dummy callbacks for ARP and conntrack processing.
	rt := routetable.NewWithShims(
		[]string{"^" + config.InterfaceName + "$"},
		4, // ipVersion
		newRoutetableNetlink,
		false, // vxlan
		netlinkTimeout,
		func(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error { return nil }, // addStaticARPEntry
		&noOpConnTrack{},
		timeShim,
		nil, //deviceRouteSourceAddress
		deviceRouteProtocol,
		true, //removeExternalRoutes
		config.RoutingTableIndex,
	)

	return &Wireguard{
		hostname:            hostname,
		config:              config,
		logCxt:              logrus.WithFields(logrus.Fields{"enabled": config.Enabled, "ifaceName": config.InterfaceName}),
		newWireguardNetlink: newWireguardNetlink,
		newWireguardDevice:  newWireguardDevice,
		time:                timeShim,
		nodes: map[string]*nodeData{
			hostname: newNodeData(),
		},
		cidrToNodeName:        map[ip.CIDR]string{},
		publicKeyToNodeNames:  map[wgtypes.Key]set.Set{},
		nodeUpdates:           map[string]*nodeUpdateData{},
		cidrToNodeNameUpdates: map[ip.CIDR]string{},
		routetable:            rt,
		statusCallback:        statusCallback,
	}
}

func (w *Wireguard) OnIfaceStateChanged(ifaceName string, state ifacemonitor.State) {
	if w.config.InterfaceName != ifaceName {
		w.logCxt.Debug("Ignoring interface state change, not the wireguard interface.")
		return
	}
	switch state {
	case ifacemonitor.StateUp:
		w.logCxt.Debug("Interface up, marking for route sync")
		if !w.ifaceUp {
			w.ifaceUp = true
			w.inSyncWireguard = false
		}
	case ifacemonitor.StateDown:
		w.logCxt.Debug("Interface up, marking for route sync")
		w.ifaceUp = false
	}
}

func (w *Wireguard) EndpointUpdate(name string, ipv4Addr ip.Addr) {
	w.logCxt.Debugf("EndpointUpdate: name=%s; ipv4Addr=%v", name, ipv4Addr)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	} else if name == w.hostname {
		return
	}

	update := w.getNodeUpdate(name)
	if existing, ok := w.nodes[name]; ok && existing.ipv4EndpointAddr == ipv4Addr {
		w.logCxt.Debug("Update contains unchanged IPv4 address")
		update.ipv4EndpointAddr = nil
	} else {
		w.logCxt.Debug("Update contains new IPv4 address")
		update.ipv4EndpointAddr = &ipv4Addr
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) EndpointRemove(name string) {
	w.logCxt.Debugf("EndpointRemove: name=%s", name)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	} else if name == w.hostname {
		w.logCxt.Debug("Local update - ignoring")
		return
	}

	if _, ok := w.nodes[name]; ok {
		// Node data exists, so store a blank update with a deleted flag. The delete will be applied first, and then any
		// subsequent updates
		w.logCxt.Debug("Existing node is flagged for removal")
		nu := newNodeUpdateData()
		nu.deleted = true
		w.setNodeUpdate(name, nu)
	} else {
		// Node data is not yet programmed so just delete the pending update.
		w.logCxt.Debug("Node removed which has not yet been programmed - remove any pending update")
		delete(w.nodeUpdates, name)
	}
}

func (w *Wireguard) EndpointAllowedCIDRAdd(name string, cidr ip.CIDR) {
	w.logCxt.Debugf("EndpointAllowedCIDRAdd: name=%s; cidr=%v", name, cidr)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	} else if name == w.hostname {
		w.logCxt.Debug("Local update - ignoring")
		return
	}

	update := w.getNodeUpdate(name)
	if existing, ok := w.nodes[name]; ok && existing.cidrs.Contains(cidr) {
		// Adding the CIDR to a node that already has it. This may happen if there is a pending CIDR deletion for the
		// node, so discard the deletion update.
		w.logCxt.Debug("Node CIDR added which is already programmed - remove any pending delete")
		update.allowedCidrsDeleted.Discard(cidr)
		delete(w.cidrToNodeNameUpdates, cidr)
	} else {
		// Adding the CIDR to a node that does not already have it.
		w.logCxt.Debug("Node CIDR added which is not programmed")
		update.allowedCidrsAdded.Add(cidr)
		w.cidrToNodeNameUpdates[cidr] = name
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) EndpointAllowedCIDRRemove(cidr ip.CIDR) {
	w.logCxt.Debugf("EndpointAllowedCIDRRemove: cidr=%v", cidr)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	}

	// Determine which node this CIDR belongs to. Check the updates first and then the processed.
	name, ok := w.cidrToNodeNameUpdates[cidr]
	if !ok {
		w.logCxt.Debugf("CIDR not found as node update, checking current configuration")
		name, ok = w.cidrToNodeName[cidr]
		if !ok {
			// The wireguard manager filters out some of the CIDR updates, but not the removes, so it's possible to get
			// CIDR removes for which we have seen no corresponding add.
			w.logCxt.Debugf("CIDR remove update but not associated with a node: %v", cidr)
			return
		}
	}
	w.logCxt.Debugf("CIDR found for node %s", name)

	update := w.getNodeUpdate(name)
	if existing, ok := w.nodes[name]; ok && existing.cidrs.Contains(cidr) {
		// Remove the CIDR from a node that already has the CIDR configured.
		w.logCxt.Debug("Node CIDR removed which is programmed")
		update.allowedCidrsDeleted.Add(cidr)
		w.cidrToNodeNameUpdates[cidr] = name
	} else {
		// Deleting the CIDR from a node that already doesn't have it. This may happen if there is a pending CIDR
		// addition for the node, so discard the addition update.
		w.logCxt.Debug("Node CIDR removed which is not programmed - remove any pending delete")
		update.allowedCidrsAdded.Discard(cidr)
		delete(w.cidrToNodeNameUpdates, cidr)
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) EndpointWireguardUpdate(name string, publicKey wgtypes.Key, ipv4InterfaceAddr ip.Addr) {
	w.logCxt.Debugf("EndpointWireguardUpdate: name=%s; key=%s, ipv4Addr=%s", name, publicKey, ipv4InterfaceAddr)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	}

	update := w.getNodeUpdate(name)
	if existing, ok := w.nodes[name]; ok {
		w.logCxt.Debug("Endpoint exists already")
		if existing.publicKey == publicKey {
			w.logCxt.Debug("Public key unchanged from programmed")
			update.publicKey = nil
		} else {
			w.logCxt.Debug("Public key updated")
			update.publicKey = &publicKey
		}

		if existing.ipv4InterfaceAddr == ipv4InterfaceAddr {
			w.logCxt.Debug("IPv4 address unchanged from programmed")
			update.ipv4InterfaceAddr = nil
		} else {
			w.logCxt.Debug("IPv4 address updated")
			update.ipv4InterfaceAddr = &ipv4InterfaceAddr
		}
	} else {
		// Adding the CIDR to a node that does not already have it.
		w.logCxt.Debug("Storing new endpoint")
		update.publicKey = &publicKey
		update.ipv4InterfaceAddr = &ipv4InterfaceAddr
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) getNode(name string) *nodeData {
	if n := w.nodes[name]; n != nil {
		return n
	}
	return newNodeData()
}

func (w *Wireguard) setNode(name string, node *nodeData) {
	w.nodes[name] = node
}

func (w *Wireguard) getNodeUpdate(name string) *nodeUpdateData {
	if nu := w.nodeUpdates[name]; nu != nil {
		return nu
	}
	return newNodeUpdateData()
}

func (w *Wireguard) setNodeUpdate(name string, update *nodeUpdateData) {
	w.nodeUpdates[name] = update
}

func (w *Wireguard) QueueResync() {
	w.logCxt.Info("Queueing a resync of routing table.")

	// Flag for resync to ensure everything is still configured correctly.
	w.inSyncWireguard = false
	w.inSyncLink = false
	w.inSyncRouteRule = false
	w.inSyncInterfaceAddr = false

	// No need to resync the key. This will happen if the dataplane resync detects an inconsistency.
	//w.inSyncKey = false

	// Flag the routetable for resync.
	w.routetable.QueueResync()
}

func (w *Wireguard) Apply() (err error) {
	// If the key is not in-sync and is known then send as a status update.
	defer func() {
		// If we need to send the key then send on the callback method.
		if !w.inSyncKey && w.ourPublicKey != nil {
			w.logCxt.Infof("Public key out of sync or updated: %s", *w.ourPublicKey)
			if errKey := w.statusCallback(*w.ourPublicKey); errKey != nil {
				err = errKey
				return
			}

			// We have sent the key status update.
			w.inSyncKey = true
		}
	}()

	// Get the netlink client - we should always be able to get this client.
	netlinkClient, err := w.getNetlinkClient()
	if err != nil {
		w.logCxt.Errorf("error obtaining link client: %v", err)
		return err
	}

	// If wireguard is not enabled, then short-circuit the processing - ensure config is deleted.
	if !w.config.Enabled {
		w.logCxt.Info("Wireguard is not enabled")
		if !w.inSyncWireguard {
			w.logCxt.Debug("Wireguard is not in-sync - verifying wireguard configuration is removed")
			if err := w.ensureDisabled(netlinkClient); err != nil {
				return err
			}
		}

		// Zero out the public key.
		w.ourPublicKey = &zeroKey
		w.inSyncWireguard = true
		return nil
	}

	// --- Wireguard is enabled ---

	// We scan the updates multiple times to perform the following ordered updates:
	// 1. Deletion of nodes and wireguard peers (we handle these separately from other updates because it is easier
	//    to handle a delete/re-add this way without needing to calculate delta configs.
	// 2. Update of cached node configuration (we cannot be certain exactly what is programmable until updated)
	// 3. Update of route table routes.
	// 4. Construction of wireguard delta (if performing deltas, or re-sync of wireguard configuration)
	// 5. Simultaneous updates of wireguard, routes and rules.
	var conflictingKeys = set.New()
	wireguardPeerDelete := w.handlePeerAndRouteDeletionFromNodeUpdates(conflictingKeys)
	w.updateCacheFromNodeUpdates(conflictingKeys)
	w.updateRouteTableFromNodeUpdates()

	// All updates have been applied. Make sure we delete them after we exit - we will either have applied the deltas,
	// or we'll need to do a full resync, in either case no need to keep the deltas.  Don't do this immediately because
	// we may need them to calculate the wireguard config delta.
	defer func() {
		w.nodeUpdates = map[string]*nodeUpdateData{}
	}()

	// If necessary ensure the wireguard device is configured. If this errors or if it is not yet oper up then no point
	// doing anything else.
	if !w.inSyncLink {
		w.logCxt.Debug("Ensure wireguard link is created and up")
		operUp, err := w.ensureLink(netlinkClient)
		if netlinkshim.IsNotSupported(err) {
			w.logCxt.Info("Wireguard is not supported - send zero-key status")
			w.ourPublicKey = &zeroKey
			return err
		} else if err != nil {
			// Error configuring link, pass up the stack.
			w.logCxt.WithError(err).Info("Unable to create wireguard link, retrying...")
			return err
		} else if !operUp {
			// Wait for oper up notification.
			w.logCxt.Info("Waiting for wireguard link to come up...")
			return nil
		}
	}

	// Get the wireguard client. This may not always be possible.
	wireguardClient, err := w.getWireguardClient()
	if err == ErrNotSupported {
		w.logCxt.Info("Wireguard is not supported - send zero-key status")
		w.ourPublicKey = &zeroKey
		return err
	} else if err != nil {
		w.logCxt.Errorf("error obtaining link client: %v", err)
		return err
	}

	// The following can be done in parallel:
	// - Update the link address
	// - Update the routetable
	// - Update the wireguard device.
	var wg sync.WaitGroup
	var errLink, errWireguard, errRoutes error

	// Update link address if out of sync.
	if !w.inSyncInterfaceAddr {
		w.logCxt.Info("Ensure wireguard interface address is correct")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if errLink = w.ensureLinkAddressV4(netlinkClient); errLink == nil {
				w.inSyncInterfaceAddr = true
			}
		}()
	}

	// Apply routetable updates.
	w.logCxt.Debug("Apply routing table updates for wireguard")
	wg.Add(1)
	go func() {
		defer wg.Done()
		errRoutes = w.routetable.Apply()
	}()

	// Apply wireguard configuration.
	w.logCxt.Debug("Apply wireguard crypto routing updates")
	wg.Add(1)
	var wireguardPeerUpdate *wgtypes.Config
	var publicKey wgtypes.Key
	go func() {
		defer wg.Done()

		// Update wireguard so that we are in-sync.
		if w.inSyncWireguard {
			// Wireguard configuration is in-sync, perform a delta update. First do the delete that was constructed
			// earlier, then construct and apply the update. Flag as not in-sync until we have finished processing.
			if errWireguard = w.applyWireguardConfig(wireguardClient, wireguardPeerDelete); errWireguard != nil {
				w.logCxt.WithError(errWireguard).Info("Failed to delete wireguard peers")
				return
			}
			wireguardPeerUpdate = w.constructWireguardDeltaFromNodeUpdates(conflictingKeys)
			if errWireguard = w.applyWireguardConfig(wireguardClient, wireguardPeerUpdate); errWireguard != nil {
				w.logCxt.WithError(errWireguard).Info("Failed to create or update wireguard peers")
				return
			}
		} else {
			// Wireguard configuration is not in-sync. Construct and apply the wireguard configuration required to
			// synchronize with our cached data.
			if publicKey, wireguardPeerUpdate, errWireguard = w.constructWireguardDeltaForResync(wireguardClient); errWireguard != nil {
				w.logCxt.WithError(errWireguard).Info("Failed to construct a full wireguard delta for resync")
				return
			} else if errWireguard = w.applyWireguardConfig(wireguardClient, wireguardPeerUpdate); errWireguard != nil {
				w.logCxt.WithError(errWireguard).Info("Failed to update wireguard peers for resync")
				return
			} else if w.ourPublicKey == nil || *w.ourPublicKey != publicKey {
				// The public key differs from the one we previously queried or this is the first time we queried it.
				// Store and flag our key is not in sync so that a status update will be sent.
				w.logCxt.Infof("Public key has been updated to %s, send status notification", publicKey)
				w.ourPublicKey = &publicKey
				w.inSyncKey = false
			}
		}
		w.inSyncWireguard = true

		// Now wireguard configuration is in sync. Update the cached node data to reflect programmed state.
		for name, node := range w.nodes {
			if w.shouldProgramWireguardPeer(node) {
				w.logCxt.Debugf("Flag node %s as programmed", name)
				node.programmedInWireguard = true
			} else {
				w.logCxt.Debugf("Flag node %s as not programmed", name)
				node.programmedInWireguard = true
			}
		}
	}()

	// Wait for the updates to complete.
	wg.Wait()

	// Return an error if we hit one - doesn't really matter which error we return though.
	if errLink != nil || errWireguard != nil || errRoutes != nil {
		return ErrUpdateFailed
	}

	// Once the wireguard and routing configuration is in place we can add the routing rule to start using the new
	// routing table.
	w.logCxt.Debug("Ensure routing rule is configured")
	if err = w.ensureRouteRule(netlinkClient); err != nil {
		return err
	}

	// Routing rule is now in-sync.
	w.inSyncRouteRule = true
	return nil
}

// handlePeerAndRouteDeletionFromNodeUpdates handles wireguard peer deletion preparation:
// -  Updates routing table to remove routes for permantently deleted peers
// -  Creates a wireguard config update for deleted peers, or for peers whose public key has changed (which for
//    wireguard is effectively a different peer)
//
// This method does not perform any dataplane updates.
func (w *Wireguard) handlePeerAndRouteDeletionFromNodeUpdates(conflictingKeys set.Set) *wgtypes.Config {
	var wireguardPeerDelete wgtypes.Config
	for name, update := range w.nodeUpdates {
		// Skip over the local node data - this can never be deleted.
		if name == w.hostname {
			continue
		}

		// Get existing node configuration. If node not seen before then no deletion processing is required.
		w.logCxt.Debugf("Handle peer and route deletion for node %s", name)
		node := w.nodes[name]
		if node == nil {
			w.logCxt.Debugf("No wireguard configuration for node %s", name)
			continue
		}

		if update.deleted {
			// Node is deleted, so remove the node configuration and the associated routes.
			w.logCxt.Infof("Node %s is deleted, remove associated routes and wireguard peer", name)
			delete(w.nodes, name)

			// Delete all of the node routes for the nodeData. Note that we always update the routing table routes using
			// delta updates even during a full resync. The routetable component takes care of its own kernel-cache
			// synchronization.
			node.cidrs.Iter(func(item interface{}) error {
				cidr := item.(ip.CIDR)
				w.routetable.RouteRemove(w.config.InterfaceName, cidr)
				w.logCxt.Debugf("Deleting route for %s", cidr)
				return nil
			})
		} else if update.publicKey == nil || *update.publicKey == node.publicKey {
			// It's not a delete, and the public key hasn't changed so no key deletion processing required.
			w.logCxt.Debugf("Node %s updated, but public key is the same, no wireguard peer deletion required", name)
			continue
		}

		if node.publicKey == zeroKey {
			// The node did not have a key assigned, so no peer tidy-up required.
			w.logCxt.Debugf("Node %s had no public key assigned, so no deletion of wireguard peer necessary", name)
			continue
		}

		// If we aren't doing a full re-sync then delete the associated peer if it was previously configured.
		if node.programmedInWireguard && w.inSyncWireguard {
			w.logCxt.Debugf("Adding peer deletion config update for key %s", node.publicKey)
			wireguardPeerDelete.Peers = append(wireguardPeerDelete.Peers, wgtypes.PeerConfig{
				PublicKey: node.publicKey,
				Remove:    true,
			})
			node.programmedInWireguard = false
		}

		// Remove the key to node reference.
		nodenames := w.publicKeyToNodeNames[node.publicKey]
		nodenames.Discard(name)
		if nodenames.Len() == 0 {
			// This was the only node with its public key
			w.logCxt.Debugf("Removed only node %s with public key %s", name, node.publicKey)
			delete(w.publicKeyToNodeNames, node.publicKey)
		} else {
			// This is or was a conflicting key. Recheck the nodes associated with this key at the end.
			w.logCxt.Infof("Removed node %s with identical public key %s to at least one other node", name, node.publicKey)
			conflictingKeys.Add(node.publicKey)
		}
		node.publicKey = zeroKey
	}

	if len(wireguardPeerDelete.Peers) > 0 {
		w.logCxt.Debug("There are wireguard peers to delete")
		return &wireguardPeerDelete
	}
	return nil
}

// updateCacheFromNodeUpdates updates the cache from the node update configuration.
//
// This method applies the current set of node updates on top of the current cache. It removes updates that are no
// ops so that they are not re-processed further down the pipeline.
func (w *Wireguard) updateCacheFromNodeUpdates(conflictingKeys set.Set) {
	for name, update := range w.nodeUpdates {
		node := w.getNode(name)
		if name == w.hostname {
			// This is the local node configuration.  If set, update the interface address.
			w.logCxt.Debugf("Processing local node %s", name)
			if update.ipv4InterfaceAddr != nil {
				w.logCxt.Debugf("Wireguard device address updated %v", *update.ipv4InterfaceAddr)
				node.ipv4InterfaceAddr = *update.ipv4InterfaceAddr
				w.inSyncInterfaceAddr = false
				w.setNode(name, node)
			}

			if update.publicKey != nil && update.publicKey != w.ourPublicKey {
				// The local public key is updated from querying or programming the dataplane rather than from the
				// calc graph. If the update is different from the dataplane value then send a status message to tell
				// the dataplane connector to fix the stored value.
				w.logCxt.Debugf("Wireguard public key is out of sync: %v", *update.publicKey)
				w.inSyncKey = false
			}

			// We don't need to do any other updates for the local configuration, so just remove this update so we
			// don't process it again.
			delete(w.nodeUpdates, name)
			continue
		}

		// This is a remote node configuration. Update the node data and the key to node mappings.
		w.logCxt.Debugf("Processing remote node %s", name)
		updated := false
		if update.ipv4EndpointAddr != nil {
			w.logCxt.Debugf("Store IPv4 address %s", *update.ipv4EndpointAddr)
			node.ipv4EndpointAddr = *update.ipv4EndpointAddr
			updated = true
		}
		if update.publicKey != nil {
			w.logCxt.Debugf("Store public key %s", *update.publicKey)
			node.publicKey = *update.publicKey
			if node.publicKey != zeroKey {
				if nodenames := w.publicKeyToNodeNames[node.publicKey]; nodenames == nil {
					w.logCxt.Debug("Public key not associated with a node")
					w.publicKeyToNodeNames[node.publicKey] = set.From(name)
				} else {
					w.logCxt.Info("Public key already associated with a node")
					conflictingKeys.Add(node.publicKey)
					nodenames.Add(name)
				}
			}
			updated = true
		}
		update.allowedCidrsDeleted.Iter(func(item interface{}) error {
			w.logCxt.Debugf("Discarding CIDR %s", item)
			node.cidrs.Discard(item)
			updated = true
			return nil
		})
		update.allowedCidrsAdded.Iter(func(item interface{}) error {
			w.logCxt.Debugf("Adding CIDR %s", item)
			node.cidrs.Add(item)
			updated = true
			return nil
		})

		if updated {
			// Node configuration updated. Store node data.
			w.logCxt.Debug("Node updated")
			w.setNode(name, node)
		} else {
			// No further update, delete update so it's not processed again.
			w.logCxt.Debug("No updates for the node - remove node update to remove additional processing")
			delete(w.nodeUpdates, name)
		}
	}
}

// updateRouteTable updates the route table from the node updates.
func (w *Wireguard) updateRouteTableFromNodeUpdates() {
	for name, update := range w.nodeUpdates {
		w.logCxt.Debugf("Processing node %s", name)
		node := w.getNode(name)

		// Delete routes that are no longer required in routing.
		update.allowedCidrsDeleted.Iter(func(item interface{}) error {
			w.logCxt.Debugf("Removing CIDR %s from routetable", item)
			cidr := item.(ip.CIDR)
			w.routetable.RouteRemove(w.config.InterfaceName, cidr)
			return nil
		})

		// If the node routing to wireguard does not match with whether we should route then we need to do a full
		// route update, otherwise do an incremental update.
		var updateSet set.Set
		shouldRouteToWireguard := w.shouldRouteToWireguard(node)
		if node.routingToWireguard != shouldRouteToWireguard {
			w.logCxt.Debug("Wireguard routing has changed - need to update full set of CIDRs")
			updateSet = node.cidrs
		} else {
			w.logCxt.Debug("Wireguard routing has changed - need to update added CIDRs")
			updateSet = update.allowedCidrsAdded
		}

		var targetType routetable.TargetType
		var ifaceName, deleteIfaceName string
		if !shouldRouteToWireguard {
			// If we should not route to wireguard then we need to use a throw directive to skip wireguard routing and
			// return to normal routing. We may also need to delete the existing route to wireguard.
			w.logCxt.Debug("Not routing to wireguard - set route type to throw")
			targetType = routetable.TargetTypeThrow
			ifaceName = routetable.InterfaceNone
			deleteIfaceName = w.config.InterfaceName
		} else {
			// If we should route to wireguard then route to the wireguard interface. We may also need to delete the
			// existing throw route that was used to circumvent wireguard routing.
			w.logCxt.Debug("Routing to wireguard interface")
			ifaceName = w.config.InterfaceName
			deleteIfaceName = routetable.InterfaceNone
		}

		updateSet.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			w.logCxt.Debugf("Updating route for CIDR %s", cidr)
			if node.routingToWireguard != shouldRouteToWireguard {
				// The wireguard setting has changed. It is possible that some of the entries we are "removing" were
				// never added - the routetable component handles that gracefully. We need to do these deletes because
				// routetable component groups by interface and we are essentially moving routes between the wireguard
				// interface and the "none" interface.
				w.logCxt.Debugf("Wireguard routing has changed - delete previous route for %s", deleteIfaceName)
				w.routetable.RouteRemove(deleteIfaceName, cidr)
			}
			w.routetable.RouteUpdate(ifaceName, routetable.Target{
				Type: targetType,
				CIDR: cidr,
			})
			return nil
		})
		node.routingToWireguard = shouldRouteToWireguard
	}
}

// constructWireguardDeltaFromNodeUpdates constructs a wireguard delta update from the set of node updates.
func (w *Wireguard) constructWireguardDeltaFromNodeUpdates(conflictingKeys set.Set) *wgtypes.Config {
	// 4. If we are performing a wireguard delta update then construct the delta now.
	var wireguardUpdate wgtypes.Config
	if w.inSyncWireguard {
		// Construct a wireguard delta update
		for name, update := range w.nodeUpdates {
			w.logCxt.Debugf("Constructing wireguard delta for node: %s", name)
			node := w.nodes[name]
			if node == nil {
				w.logCxt.Warning("internal error: node data is nil")
				continue
			}
			if name == w.hostname {
				w.logCxt.Warning("internal error: processing local node as peer")
				continue
			}

			if w.shouldProgramWireguardPeer(node) {
				// The peer should be programmed in wireguard. We need to do a full CIDR re-sync if either:
				// -  A CIDR was deleted (there is no API directive for deleting an allowed CIDR), or
				// -  The peer has not been programmed.
				w.logCxt.Debug("Peer should be programmed")
				peer := wgtypes.PeerConfig{
					UpdateOnly: node.programmedInWireguard,
					PublicKey:  node.publicKey,
				}
				updatePeer := false
				if !node.programmedInWireguard || update.allowedCidrsDeleted.Len() > 0 {
					w.logCxt.Debug("Peer not programmed or CIDRs were deleted - need to replace full set of CIDRs")
					peer.ReplaceAllowedIPs = true
					peer.AllowedIPs = node.allowedCidrsForWireguard()
					updatePeer = true
				} else if update.allowedCidrsAdded.Len() > 0 {
					w.logCxt.Debug("Peer programmmed, no CIDRs deleted and CIDRs added")
					peer.AllowedIPs = make([]net.IPNet, 0, update.allowedCidrsAdded.Len())
					update.allowedCidrsAdded.Iter(func(item interface{}) error {
						peer.AllowedIPs = append(peer.AllowedIPs, item.(ip.CIDR).ToIPNet())
						return nil
					})
					updatePeer = true
				}

				if update.ipv4EndpointAddr != nil {
					w.logCxt.Infof("Peer endpoint address is updated: %s", *update.ipv4EndpointAddr)
					peer.Endpoint = &net.UDPAddr{
						IP:   node.ipv4EndpointAddr.AsNetIP(),
						Port: w.config.ListeningPort,
					}
					updatePeer = true
				}

				if updatePeer {
					w.logCxt.Debugf("Peer needs updating")
					wireguardUpdate.Peers = append(wireguardUpdate.Peers, peer)
					node.programmedInWireguard = true
				}
			} else if node.programmedInWireguard {
				// This node is programmed in wireguard and it should not be. Add a delta delete.
				w.logCxt.Debug("Peer should not be programmed")
				wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
					Remove:    true,
					PublicKey: node.publicKey,
				})
				node.programmedInWireguard = false
			}

			w.nodes[name] = node
		}

		// Finally loop through any conflicting public keys and check each of the nodes is now handled correctly.
		conflictingKeys.Iter(func(item interface{}) error {
			w.logCxt.Debugf("Processing public key with conflicting nodes: %s", item)
			nodenames := w.publicKeyToNodeNames[item.(wgtypes.Key)]
			if nodenames == nil {
				return nil
			}
			nodenames.Iter(func(nodename interface{}) error {
				w.logCxt.Debugf("Processing node %s", nodename)
				node := w.nodes[nodename.(string)]
				if node == nil || node.programmedInWireguard == w.shouldProgramWireguardPeer(node) {
					// The node programming matches the expected value, so nothing to do.
					w.logCxt.Debug("Programming state has not changed")
					return nil
				} else if node.programmedInWireguard {
					// The node is programmed and shouldn't be. Add a delta delete.
					w.logCxt.Debug("Programmed in wireguard, need to delete")
					wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
						Remove:    true,
						PublicKey: node.publicKey,
					})
					node.programmedInWireguard = false
				} else {
					// The node is not programmed and should be.  Add a delta create.
					w.logCxt.Debug("Programmed is not in wireguard, needs to be added now")
					wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
						PublicKey:  node.publicKey,
						AllowedIPs: node.allowedCidrsForWireguard(),
					})
					node.programmedInWireguard = true
				}
				return nil
			})
			return nil
		})
	}

	// Delta updates only include updates to peer config, so if no peer updates, just return nil.
	if len(wireguardUpdate.Peers) > 0 {
		w.logCxt.Debug("There are peers to update")
		return &wireguardUpdate
	}
	return nil
}

// constructWireguardDeltaForResync checks the wireguard configuration matches the cached data and creates a delta
// update to correct any discrepancies.
func (w *Wireguard) constructWireguardDeltaForResync(wireguardClient netlinkshim.Wireguard) (wgtypes.Key, *wgtypes.Config, error) {
	// Get the wireguard device configuration.
	device, err := wireguardClient.DeviceByName(w.config.InterfaceName)
	if err != nil {
		w.logCxt.Errorf("error querying wireguard configuration: %v", err)
		return zeroKey, nil, err
	}

	// Determine if any configuration on the device needs updating
	wireguardUpdate := wgtypes.Config{}
	wireguardUpdateRequired := false
	if device.FirewallMark != w.config.FirewallMark {
		w.logCxt.Infof("Update firewall mark from %d to %d", device.FirewallMark, w.config.FirewallMark)
		wireguardUpdate.FirewallMark = &w.config.FirewallMark
		wireguardUpdateRequired = true
	}
	if device.ListenPort != w.config.ListeningPort {
		w.logCxt.Infof("Update listening port from %d to %d", device.ListenPort, w.config.ListeningPort)
		wireguardUpdate.ListenPort = &w.config.ListeningPort
		wireguardUpdateRequired = true
	}

	publicKey := device.PublicKey
	if device.PrivateKey == zeroKey || device.PublicKey == zeroKey {
		// One of the private or public key is not set. Generate a new private key and return the corresponding
		// public key.
		w.logCxt.Info("Generate new private/public keypair")
		pkey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			w.logCxt.Errorf("error generating private-key: %v", err)
			return zeroKey, nil, err
		}
		wireguardUpdate.PrivateKey = &pkey
		wireguardUpdateRequired = true

		publicKey = pkey.PublicKey()
	}

	// Track which keys we have processed. The value indicates whether the data should be programmed in wireguard or
	// not.
	processedKeys := set.New()

	// Handle peers that are configured
	for peerIdx := range device.Peers {
		key := device.Peers[peerIdx].PublicKey
		node := w.getNodeFromKey(key)
		if node == nil {
			w.logCxt.Infof("Peer key is not expected or associated with multiple nodes: %v", key)
			wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
				PublicKey: key,
				Remove:    true,
			})
			processedKeys.Add(key)
			wireguardUpdateRequired = true
			continue
		}

		w.logCxt.Debugf("Checking allowed CIDRs for node with key %v", key)
		configuredCidrs := device.Peers[peerIdx].AllowedIPs
		configuredAddr := device.Peers[peerIdx].Endpoint
		replaceCidrs := false
		if len(configuredCidrs) == node.cidrs.Len() {
			// Same number of allowed IPs configured and cached.  Check for discrepancies.
			w.logCxt.Debug("Number of CIDRs matches")
			for _, netCidr := range configuredCidrs {
				cidr := ip.CIDRFromIPNet(&netCidr)
				if !node.cidrs.Contains(cidr) {
					// Need to delete an entry, so just replace
					w.logCxt.Debugf("Unexpected CIDR configured: %s", cidr)
					replaceCidrs = true
					break
				}
			}
		}

		// If the CIDRs need replacing or the endpoint address needs updating then wireguardUpdate the entry.
		expectedEndpointIP := node.ipv4EndpointAddr.AsNetIP()
		if replaceCidrs || configuredAddr == nil || configuredAddr.Port != w.config.ListeningPort || !configuredAddr.IP.Equal(expectedEndpointIP) {
			peer := wgtypes.PeerConfig{
				PublicKey:         key,
				UpdateOnly:        true,
				ReplaceAllowedIPs: replaceCidrs,
			}

			if configuredAddr == nil || configuredAddr.Port != w.config.ListeningPort || !configuredAddr.IP.Equal(expectedEndpointIP) {
				w.logCxt.Info("Endpoint address needs updating")
				peer.Endpoint = &net.UDPAddr{
					IP:   expectedEndpointIP,
					Port: w.config.ListeningPort,
				}
			}

			if replaceCidrs {
				w.logCxt.Info("AllowedIPs need replacing")
				peer.AllowedIPs = node.allowedCidrsForWireguard()
			}

			wireguardUpdate.Peers = append(wireguardUpdate.Peers, peer)
			wireguardUpdateRequired = true
		}
	}

	// Handle peers that are not configured at all.
	for name, node := range w.nodes {
		if processedKeys.Contains(node.publicKey) {
			w.logCxt.Debugf("Peer key already handled: node %s; key %v", name, node.publicKey)
			continue
		}
		if w.shouldProgramWireguardPeer(node) {
			w.logCxt.Debugf("Peer should not be programmed: node %s", name)
			continue
		}

		w.logCxt.Infof("Add peer to wireguard: node %s; key %v", name, node.publicKey)
		wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
			PublicKey: node.publicKey,
			Endpoint: &net.UDPAddr{
				IP:   node.ipv4EndpointAddr.AsNetIP(),
				Port: w.config.ListeningPort,
			},
			AllowedIPs: node.allowedCidrsForWireguard(),
		})
		wireguardUpdateRequired = true
	}

	w.logCxt.Debugf("Wireguard device configured with public key %v", publicKey)

	if wireguardUpdateRequired {
		return publicKey, &wireguardUpdate, nil
	}

	return publicKey, nil, nil
}

// ensureLink checks that the wireguard link is configured correctly. Returns true if the link is oper up.
func (w *Wireguard) ensureLink(netlinkClient netlinkshim.Netlink) (bool, error) {
	link, err := netlink.LinkByName(w.config.InterfaceName)
	if netlinkshim.IsNotExist(err) {
		// Create the wireguard device.
		w.logCxt.Info("Wireguard device needs to be created")
		attr := netlink.NewLinkAttrs()
		attr.Name = w.config.InterfaceName
		lwg := netlink.GenericLink{
			LinkAttrs: attr,
			LinkType:  wireguardType,
		}

		if err := netlinkClient.LinkAdd(&lwg); err != nil {
			w.logCxt.Errorf("error adding wireguard type link: %v", err)
			return false, err
		}

		link, err = netlinkClient.LinkByName(w.config.InterfaceName)
		if err != nil {
			w.logCxt.Errorf("error querying wireguard device: %v", err)
			return false, err
		}

		w.logCxt.Info("Created wireguard device")
	} else if err != nil {
		w.logCxt.Errorf("unable to determine if wireguard device exists: %v", err)
		return false, err
	}

	if link.Type() != wireguardType {
		w.logCxt.Errorf("interface %s is of type %s, not wireguard", w.config.InterfaceName, link.Type())
		return false, errWrongInterfaceType
	}

	// If necessary, update the MTU and admin status of the device.
	w.logCxt.Debug("Wireguard device exists, checking settings")
	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if w.config.MTU != 0 && oldMTU != w.config.MTU {
		w.logCxt.WithField("oldMTU", oldMTU).Info("Wireguard device MTU needs to be updated")
		if err := netlinkClient.LinkSetMTU(link, w.config.MTU); err != nil {
			w.logCxt.WithError(err).Warn("failed to set tunnel device MTU")
			return false, err
		}
		w.logCxt.Info("Updated tunnel MTU")
	}
	if attrs.Flags&net.FlagUp == 0 {
		w.logCxt.WithField("flags", attrs.Flags).Info("Wireguard interface wasn't admin up, enabling it")
		if err := netlinkClient.LinkSetUp(link); err != nil {
			w.logCxt.WithError(err).Warn("failed to set wireguard device up")
			return false, err
		}
		w.logCxt.Info("Set wireguard admin up")
	}

	// Track whether the interface is oper up or not. We halt programming when it is down.
	return attrs.OperState == netlink.OperUp, nil
}

// ensureNoLink checks that the wireguard link is not present.
func (w *Wireguard) ensureNoLink(netlinkClient netlinkshim.Netlink) error {
	link, err := netlinkClient.LinkByName(w.config.InterfaceName)
	if err == nil {
		// Wireguard device exists.
		w.logCxt.Info("Wireguard is disabled, deleting device")
		if err := netlinkClient.LinkDel(link); err != nil {
			w.logCxt.Errorf("error deleting wireguard type link: %v", err)
			return err
		}
		w.logCxt.Info("Deleted wireguard device")
	} else if netlinkshim.IsNotExist(err) {
		w.logCxt.Debug("Wireguard is disabled and does not exist")
	} else if err != nil {
		w.logCxt.Errorf("unable to determine if wireguard device exists: %v", err)
		return err
	}
	return nil
}

// ensureLinkAddressV4 ensures the wireguard link to set to the required local IP address.  It removes any other
// addresses.
func (w *Wireguard) ensureLinkAddressV4(netlinkClient netlinkshim.Netlink) error {
	w.logCxt.Debug("Setting local IPv4 address on link.")
	link, err := netlinkClient.LinkByName(w.config.InterfaceName)
	if err != nil {
		w.logCxt.WithError(err).Warning("Failed to get device")
		return err
	}

	addrs, err := netlinkClient.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		w.logCxt.WithError(err).Warn("failed to list interface addresses")
		return err
	}

	var address net.IP
	if node, ok := w.nodes[w.hostname]; ok && node.ipv4InterfaceAddr != nil {
		address = node.ipv4InterfaceAddr.AsNetIP()
	}

	found := false
	for _, oldAddr := range addrs {
		if address != nil && oldAddr.IP.Equal(address) {
			w.logCxt.Debug("Address already present.")
			found = true
			continue
		}
		w.logCxt.WithField("oldAddr", oldAddr).Info("Removing old address")
		if err := netlinkClient.AddrDel(link, &oldAddr); err != nil {
			w.logCxt.WithError(err).Warn("failed to delete address from wireguard device")
			return err
		}
	}

	if !found && address != nil {
		w.logCxt.Info("address not present on wireguard device, adding it")
		mask := net.CIDRMask(32, 32)
		ipNet := net.IPNet{
			IP:   address.Mask(mask), // Mask the IP to match ParseCIDR()'s behaviour.
			Mask: mask,
		}
		addr := &netlink.Addr{
			IPNet: &ipNet,
		}
		if err := netlinkClient.AddrAdd(link, addr); err != nil {
			w.logCxt.WithError(err).WithField("addr", address).Warn("failed to add address")
			return err
		}
	}
	w.logCxt.Debug("Address set.")

	return nil
}

func (w *Wireguard) ensureRouteRule(netlinkClient netlinkshim.Netlink) error {
	// Add rule attributes.
	rule := netlink.NewRule()
	rule.Priority = w.config.RoutingRulePriority
	rule.Table = w.config.RoutingTableIndex
	rule.Mark = w.config.FirewallMark

	if err := netlinkClient.RuleAdd(rule); err != nil && !netlinkshim.IsExist(err) {
		w.logCxt.WithError(err).Error("Unable to create wireguard routing rule")
		w.closeNetlinkClient()
		return err
	} else {
		w.logCxt.Debugf("Added rule: %#v", rule)
	}

	return nil
}

func (w *Wireguard) ensureNoRouteRule(netlinkClient netlinkshim.Netlink) error {
	// Add rule attributes.
	rule := netlink.NewRule()
	rule.Priority = w.config.RoutingRulePriority
	rule.Table = w.config.RoutingTableIndex
	rule.Mark = w.config.FirewallMark

	if err := netlinkClient.RuleDel(rule); err != nil && !netlinkshim.IsNotExist(err) {
		w.logCxt.WithError(err).Error("Unable to delete wireguard routing rule")
		w.closeNetlinkClient()
		return err
	} else {
		w.logCxt.Debugf("Deleted rule: %s", rule)
	}

	return nil
}

// ensureDisabled ensures all calico-installed wireguard configuration is removed.
func (w *Wireguard) ensureDisabled(netlinkClient netlinkshim.Netlink) error {
	var errRule, errLink, errRoutes error
	wg := sync.WaitGroup{}

	wg.Add(3)
	go func() {
		defer wg.Done()
		errRule = w.ensureNoRouteRule(netlinkClient)
	}()
	go func() {
		defer wg.Done()
		errLink = w.ensureNoLink(netlinkClient)
	}()
	go func() {
		defer wg.Done()
		// The routetable configuration will be empty since we will not send updates, so applying this will remove the
		// old routes if so configured.
		errRoutes = w.routetable.Apply()
	}()
	wg.Wait()

	if errRule != nil || errLink != nil || errRoutes != nil {
		return ErrUpdateFailed
	}
	return nil
}

func (w *Wireguard) shouldRouteToWireguard(node *nodeData) bool {
	return w.shouldProgramWireguardPeer(node)
}

func (w *Wireguard) shouldProgramWireguardPeer(node *nodeData) bool {
	// The wireguard peer should be programmed when both the IPv4 address and public key are known *and* when there
	// is only a single node owning that public key.
	return node.ipv4EndpointAddr != nil && node.publicKey != zeroKey && w.publicKeyToNodeNames[node.publicKey].Len() == 1
}

func (w *Wireguard) getWireguardClient() (netlinkshim.Wireguard, error) {
	if w.cachedWireguard == nil {
		if w.numConsistentWireguardClientFailures >= maxConnFailures && w.numConsistentWireguardClientFailures%wireguardClientRetryInterval != 0 {
			// It is a valid condition that we cannot connect to the wireguard client, so just log.
			w.logCxt.WithField("numFailures", w.numConsistentWireguardClientFailures).Debug(
				"Repeatedly failed to connect to wireguard client.")
			return nil, ErrNotSupported
		}
		w.logCxt.Info("Trying to connect to wireguard client")
		client, err := w.newWireguardDevice()
		if err != nil {
			w.numConsistentWireguardClientFailures++
			w.logCxt.WithError(err).WithField("numFailures", w.numConsistentWireguardClientFailures).Info(
				"Failed to connect to wireguard client")
			return nil, err
		}
		w.cachedWireguard = client
	}
	if w.numConsistentWireguardClientFailures > 0 {
		w.logCxt.WithField("numFailures", w.numConsistentWireguardClientFailures).Info(
			"Connected to linkClient after previous failures.")
		w.numConsistentWireguardClientFailures = 0
	}
	return w.cachedWireguard, nil
}

func (w *Wireguard) closeWireguardClient() {
	if w.cachedWireguard == nil {
		return
	}
	if err := w.cachedWireguard.Close(); err != nil {
		w.logCxt.WithError(err).Error("Failed to close wireguard client, ignoring.")
	}
	w.cachedWireguard = nil
}

// getNetlinkClient returns a netlink client for managing device links.
func (w *Wireguard) getNetlinkClient() (netlinkshim.Netlink, error) {
	if w.cachedNetlinkClient == nil {
		// We do not expect the standard netlink client to fail, so panic after a set number of failed attempts.
		if w.numConsistentLinkClientFailures >= maxConnFailures {
			w.logCxt.WithField("numFailures", w.numConsistentLinkClientFailures).Panic(
				"Repeatedly failed to connect to netlink.")
		}
		w.logCxt.Info("Trying to connect to linkClient")
		client, err := w.newWireguardNetlink()
		if err != nil {
			w.numConsistentLinkClientFailures++
			w.logCxt.WithError(err).WithField("numFailures", w.numConsistentLinkClientFailures).Error(
				"Failed to connect to linkClient")
			return nil, err
		}
		w.cachedNetlinkClient = client
	}
	if w.numConsistentLinkClientFailures > 0 {
		w.logCxt.WithField("numFailures", w.numConsistentLinkClientFailures).Info(
			"Connected to linkClient after previous failures.")
		w.numConsistentLinkClientFailures = 0
	}
	return w.cachedNetlinkClient, nil
}

// closeNetlinkClient
func (w *Wireguard) closeNetlinkClient() {
	if w.cachedNetlinkClient == nil {
		return
	}
	w.cachedNetlinkClient.Delete()
	w.cachedNetlinkClient = nil
}

// getNodeFromKey returns the node data associated with a key. If there is no node, or if multiple nodes have claimed the
// same key, this returns nil.
func (w *Wireguard) getNodeFromKey(key wgtypes.Key) *nodeData {
	if nodenames := w.publicKeyToNodeNames[key]; nodenames != nil && nodenames.Len() == 1 {
		return w.nodes[getFirstItem(nodenames).(string)]
	}
	return nil
}

func (w *Wireguard) applyWireguardConfig(wireguardClient netlinkshim.Wireguard, c *wgtypes.Config) error {
	if c == nil {
		return nil
	} else if err := wireguardClient.ConfigureDevice(w.config.InterfaceName, *c); err != nil {
		w.closeWireguardClient()
		w.inSyncWireguard = false
		return err
	}
	return nil
}

func getFirstItem(s set.Set) interface{} {
	var i interface{}
	s.Iter(func(item interface{}) error {
		i = item
		return set.StopIteration
	})
	return i
}
