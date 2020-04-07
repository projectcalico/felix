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
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/routetable"
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
	WireguardNotSupported = errors.New("wireguard not supported")

	zeroKey = wgtypes.Key{}
)

const (
	wireguardType = "wireguard"
)

type noOpConnTrack struct{}

func (*noOpConnTrack) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {
	return
}

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
	newNetlinkClient                     func() (NetlinkClient, error)
	newWireguardClient                   func() (WireguardClient, error)
	cachedNetlinkClient                  NetlinkClient
	cachedWireguardClient                WireguardClient
	numConsistentLinkClientFailures      int
	numConsistentWireguardClientFailures int
	time                                 timeIface

	// State information.
	inSyncWireguard     bool
	inSyncLink          bool
	inSyncInterfaceAddr bool
	inSyncKey           bool
	inSyncRouteRule     bool
	ifaceUp             bool
	ifacePublicKey      wgtypes.Key

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
		routetable.NewNetlinkHandle,
		newLinkClient,
		newWireguardClient,
		netlinkTimeout,
		newTimeIface(),
		deviceRouteProtocol,
		statusCallback,
	)
}

// NewWithShims is a test constructor, which allows linkClient, arp and time to be replaced by shims.
func NewWithShims(
	hostname string,
	config *Config,
	newRoutetableHandle func() (routetable.HandleIface, error),
	newNetlinkClient func() (NetlinkClient, error),
	newWireguardClient func() (WireguardClient, error),
	netlinkTimeout time.Duration,
	timeShim timeIface,
	deviceRouteProtocol int,
	statusCallback func(publicKey wgtypes.Key) error,
) *Wireguard {
	// Create routetable. We provide dummy callbacks for ARP and conntrack processing.
	rt := routetable.NewWithShims(
		[]string{config.InterfaceName}, false,
		4, // ipVersion
		newRoutetableHandle,
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
		hostname:           hostname,
		config:             config,
		logCxt:             logrus.WithFields(logrus.Fields{"enabled": config.Enabled, "ifaceName": config.InterfaceName}),
		newNetlinkClient:   newNetlinkClient,
		newWireguardClient: newWireguardClient,
		time:               timeShim,
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
	logCxt := w.logCxt.WithField("ifaceName", ifaceName)
	if w.config.InterfaceName != ifaceName {
		logCxt.Debug("Ignoring interface state change, not the wireguard interface.")
		return
	}
	switch state {
	case ifacemonitor.StateUp:
		logCxt.Debug("Interface up, marking for route sync")
		if !w.ifaceUp {
			w.ifaceUp = true
			w.inSyncWireguard = false
		}
	case ifacemonitor.StateDown:
		logCxt.Debug("Interface up, marking for route sync")
		w.ifaceUp = false
	}
}

func (w *Wireguard) EndpointUpdate(name string, ipv4Addr ip.Addr) {
	w.logCxt.Debugf("EndpointUpdate: name=%s; ipv4Addr=%v", name, ipv4Addr)
	if !w.config.Enabled {
		return
	} else if name == w.hostname {
		return
	}

	update := w.getNodeUpdate(name)
	if existing, ok := w.nodes[name]; ok && existing.ipv4EndpointAddr == ipv4Addr {
		update.ipv4EndpointAddr = nil
	} else {
		update.ipv4EndpointAddr = &ipv4Addr
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) EndpointRemove(name string) {
	w.logCxt.Debug("EndpointRemove: name=%s", name)
	if !w.config.Enabled {
		return
	} else if name == w.hostname {
		return
	}

	if _, ok := w.nodes[name]; ok {
		// Node data exists, so store a blank update with a deleted flag.
		nu := newNodeUpdateData()
		nu.deleted = true
		w.setNodeUpdate(name, nu)
	} else {
		// Node data is not yet programmed so just delete the pending update.
		delete(w.nodeUpdates, name)
	}
}

func (w *Wireguard) EndpointAllowedCIDRAdd(name string, cidr ip.CIDR) {
	w.logCxt.Debug("EndpointAllowedCIDRAdd: name=%s; cidr=%v", name, cidr)
	if !w.config.Enabled {
		return
	} else if name == w.hostname {
		return
	}

	update := w.getNodeUpdate(name)
	if existing, ok := w.nodes[name]; ok && existing.cidrs.Contains(cidr) {
		// Adding the CIDR to a node that already has it. Discard the CIDR update for the node.
		update.allowedCidrsAdded.Discard(cidr)
		update.allowedCidrsDeleted.Discard(cidr)
		delete(w.cidrToNodeNameUpdates, cidr)
	} else {
		// Adding the CIDR to a node that does not already have it.
		update.allowedCidrsAdded.Add(cidr)
		update.allowedCidrsDeleted.Discard(cidr)
		w.cidrToNodeNameUpdates[cidr] = name
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) EndpointAllowedCIDRRemove(cidr ip.CIDR) {
	if !w.config.Enabled {
		return
	}

	// Determine which node this CIDR belongs to. Check the updates first and then the processed.
	name, ok := w.cidrToNodeNameUpdates[cidr]
	if !ok {
		name, ok = w.cidrToNodeName[cidr]
		if !ok {
			w.logCxt.Errorf("CIDR remove update but not associated with a node: %v", cidr)
			return
		}
	}

	update := w.getNodeUpdate(name)
	if existing, ok := w.nodes[name]; ok && existing.cidrs.Contains(cidr) {
		// Adding the CIDR to a node that already has it. Discard the CIDR update for the node.
		update.allowedCidrsAdded.Discard(cidr)
		update.allowedCidrsDeleted.Discard(cidr)
		delete(w.cidrToNodeNameUpdates, cidr)
	} else {
		// Adding the CIDR to a node that does not already have it.
		update.allowedCidrsAdded.Add(cidr)
		update.allowedCidrsDeleted.Discard(cidr)
		w.cidrToNodeNameUpdates[cidr] = name
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) EndpointWireguardUpdate(name string, publicKey wgtypes.Key, ipv4InterfaceAddr ip.Addr) {
	if !w.config.Enabled {
		return
	}

	update := w.getNodeUpdate(name)
	if existing, ok := w.nodes[name]; ok {
		if existing.publicKey == publicKey {
			update.publicKey = nil
		} else {
			update.publicKey = &publicKey
		}

		if existing.ipv4InterfaceAddr == ipv4InterfaceAddr {
			update.ipv4InterfaceAddr = nil
		} else {
			update.ipv4InterfaceAddr = &ipv4InterfaceAddr
		}
	} else {
		// Adding the CIDR to a node that does not already have it.
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

func (w *Wireguard) Apply() error {
	// If wireguard is not enabled, then short-circuit the processing - ensure config is deleted.
	if !w.config.Enabled {
		if !w.inSyncWireguard {
			if err := w.ensureDisabled(); err != nil {
				return err
			}
		}
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
	wireguardPeerDelete := w.handleAsyncPeerDeletionsFromNodeUpdates(conflictingKeys)
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
		if operUp, err := w.ensureLink(); err != nil {
			// Error configuring link, pass up the stack.
			return err
		} else if !operUp {
			// Wait for oper up notification.
			return nil
		}
	}

	// The following can be done in parallel:
	// - Update the link address
	// - Update the routetable
	// - Update the wireguard device.
	var wg sync.WaitGroup

	var errIf, errKey, errWg, errRt, errRu error

	// Update link address if out of sync.
	if !w.inSyncInterfaceAddr {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if errIf = w.ensureLinkAddressV4(); errIf == nil {
				w.inSyncInterfaceAddr = true
			}
		}()
	}

	// Apply routetable updates.
	wg.Add(1)
	go func() {
		defer wg.Done()
		errRt = w.routetable.Apply()
	}()

	// Apply wireguard configuration.
	wg.Add(1)
	var wireguardPeerUpdate *wgtypes.Config
	var publicKey wgtypes.Key
	go func() {
		defer wg.Done()

		// Update wireguard so that we are in-sync.
		if w.inSyncWireguard {
			// Wireguard configuration is in-sync, perform a delta update. First do the delete that was constructed
			// earlier, then construct and apply the update. Flag as not in-sync until we have finised processing.
			w.inSyncWireguard = true
			if errWg = w.applyWireguardConfig(wireguardPeerDelete); errWg != nil {
				return
			}
			wireguardPeerUpdate = w.constructWireguardDeltaFromNodeUpdates(conflictingKeys)
			if errWg = w.applyWireguardConfig(wireguardPeerDelete); errWg != nil {
				return
			}
		} else {
			// Wireguard configuration is not in-sync. Construct and apply the wireguard configuration required to
			// synchronize with our cached data.
			if publicKey, wireguardPeerUpdate, errWg = w.constructWireguardDeltaForResync(); errWg != nil {
				return
			} else if errWg = w.applyWireguardConfig(wireguardPeerDelete); errWg != nil {
				return
			} else if publicKey != w.nodes[w.hostname].publicKey {
				// The public key differs from the one we have been notified of. Our key is not in-sync.
				w.inSyncKey = false
			}
		}
		w.inSyncWireguard = true

		// Now wireguard configuration is in sync. Update the cached node data to reflect programmed state.
		for name, node := range w.nodes {
			node.programmedInWireguard = w.shouldProgramWireguardPeer(node)
			w.logCxt.Debug("Flagged node as programmed: %s=%v", name, node.programmedInWireguard)
		}
	}()

	// Wait for the updates to complete.
	wg.Wait()

	// Once the wireguard and routing configuration is in place we can add the routing rule to start using the new
	// routing table.
	if errWg == nil && errRt == nil && !w.inSyncRouteRule {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if errRu = w.ensureRouteRule(); errRu == nil {
				w.inSyncRouteRule = true
			}
		}()
	}

	// If we need to send the key then send on the callback method.
	if !w.inSyncKey {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ourNode := w.nodes[w.hostname]; ourNode != nil && ourNode.publicKey != zeroKey {
				if errKey = w.statusCallback(ourNode.publicKey); errKey == nil {
					w.inSyncKey = true
				}
			}
		}()
	}

	// Wait for the status update and route rule updates to complete.
	wg.Wait()

	// If any of our updates errored, return an appropriate error.

	return nil
}

// handleAsyncPeerDeletions handles wireguard peer deletion preparation:
// -  Updates routing table to remove routes for permantently deleted peers
// -  Creates a wireguard config update for deleted peers, or for peers whose public key has changed (which for
//    wireguard is effectively a different peer)
//
// This method does not perform any dataplane updates.
func (w *Wireguard) handleAsyncPeerDeletionsFromNodeUpdates(conflictingKeys set.Set) *wgtypes.Config {
	var wireguardPeerDelete wgtypes.Config
	for name, update := range w.nodeUpdates {
		// Skip over the local node data - this can never be deleted.
		if name == w.hostname {
			continue
		}

		// Get existing node configuration. If node not seen before then no deletion processing is required.
		node := w.nodes[name]
		if node == nil {
			continue
		}

		if update.deleted {
			// Node is deleted, so remove the node configuration and the associated routes.
			delete(w.nodes, name)

			// Delete all of the node routes for the nodeData.
			node.cidrs.Iter(func(item interface{}) error {
				cidr := item.(ip.CIDR)
				w.routetable.RouteRemove(w.config.InterfaceName, cidr)
				return nil
			})
		} else if update.publicKey == nil || *update.publicKey == node.publicKey {
			// It's not a delete, and the public key hasn't changed so no key deletion processing required.
			continue
		}

		if node.publicKey == zeroKey {
			// The node did not have a key assigned, so no peer tidy-up required.
			continue
		}

		// If we aren't doing a full re-sync then delete the associated peer if it was previously configured.
		if node.programmedInWireguard && w.inSyncWireguard {
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
			delete(w.publicKeyToNodeNames, node.publicKey)
		} else {
			// This is or was a conflicting key. Recheck the nodes associated with this key at the end.
			conflictingKeys.Add(node.publicKey)
		}
		node.publicKey = zeroKey
	}

	if len(wireguardPeerDelete.Peers) > 0 {
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
			if update.ipv4InterfaceAddr != nil {
				node.ipv4InterfaceAddr = *update.ipv4InterfaceAddr
				w.inSyncInterfaceAddr = false
				w.setNode(name, node)
			}

			if update.publicKey != nil && node.publicKey != zeroKey && *update.publicKey != node.publicKey {
				// The local public key is updated from querying or programming the dataplane rather than from the
				// calc graph. If the update is different from the dataplane value then send a status message to fix
				// the updated value.
				w.inSyncKey = false
			}

			// We don't need to do any other updates for the local configuration, so just remove this update so we
			// don't process it again.
			delete(w.nodeUpdates, name)
			continue
		}

		// This is a remote node configuration. Update the node data and th key to node mappings.
		updated := false
		if update.ipv4EndpointAddr != nil {
			node.ipv4EndpointAddr = *update.ipv4EndpointAddr
			updated = true
		}
		if update.publicKey != nil {
			node.publicKey = *update.publicKey
			if node.publicKey != zeroKey {
				if nodenames := w.publicKeyToNodeNames[node.publicKey]; nodenames == nil {
					w.publicKeyToNodeNames[node.publicKey] = set.From(name)
				} else {
					conflictingKeys.Add(node.publicKey)
					nodenames.Add(name)
				}
			}
			updated = true
		}
		update.allowedCidrsDeleted.Iter(func(item interface{}) error {
			node.cidrs.Discard(item)
			updated = true
			return nil
		})
		update.allowedCidrsAdded.Iter(func(item interface{}) error {
			node.cidrs.Add(item)
			updated = true
			return nil
		})

		if updated {
			// Node configuration updated. Store node data.
			w.nodes[name] = node
		} else {
			// No further update, delete update so it's not processed again.
			delete(w.nodeUpdates, name)
		}
	}
}

// updateRouteTable updates the route table from the node updates.
func (w *Wireguard) updateRouteTableFromNodeUpdates() {
	for name, update := range w.nodeUpdates {
		node := w.getNode(name)

		// Delete routes that are no longer required in routing.
		update.allowedCidrsDeleted.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			w.routetable.RouteRemove(w.config.InterfaceName, cidr)
			return nil
		})

		// If the node routing to wireguard does not match with whether we should route then we need to do a full
		// route update, otherwise do an incremental update.
		var updateSet set.Set
		shouldRouteToWireguard := w.shouldRouteToWireguard(node)
		if node.routingToWireguard != shouldRouteToWireguard {
			updateSet = node.cidrs
		} else {
			updateSet = update.allowedCidrsAdded
		}

		var targetType routetable.TargetType
		var ifaceName, deleteIfaceName string
		if shouldRouteToWireguard {
			// If we should not route to wireguard then we need to use a throw directive to skip wireguard routing and
			// return to normal routing. We may also need to delete the existing route to wireguard.
			targetType = routetable.TargetTypeThrow
			ifaceName = routetable.InterfaceNone
			deleteIfaceName = w.config.InterfaceName
		} else {
			// If we should route to wireguard then route to the wireguard interface. We may also need to delete the
			// existing throw route that was used to circumvent wireguard routing.
			ifaceName = w.config.InterfaceName
			deleteIfaceName = routetable.InterfaceNone
		}

		updateSet.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			if node.routingToWireguard != shouldRouteToWireguard {
				// The wireguard setting has changed. It is possible that some of the entries we are "removing" were
				// never added - the routetable component handles that gracefully.
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
				peer := wgtypes.PeerConfig{
					UpdateOnly: node.programmedInWireguard,
					PublicKey:  node.publicKey,
				}
				updatePeer := false
				if !node.programmedInWireguard || update.allowedCidrsDeleted.Len() > 0 {
					peer.ReplaceAllowedIPs = true
					peer.AllowedIPs = node.allowedCidrsForWireguard()
					updatePeer = true
				} else if update.allowedCidrsAdded.Len() > 0 {
					peer.AllowedIPs = make([]net.IPNet, 0, update.allowedCidrsAdded.Len())
					update.allowedCidrsAdded.Iter(func(item interface{}) error {
						peer.AllowedIPs = append(peer.AllowedIPs, item.(ip.CIDR).ToIPNet())
						return nil
					})
					updatePeer = true
				}

				if update.ipv4EndpointAddr != nil {
					peer.Endpoint = &net.UDPAddr{
						IP:   node.ipv4EndpointAddr.AsNetIP(),
						Port: w.config.ListeningPort,
					}
					updatePeer = true
				}

				if updatePeer {
					wireguardUpdate.Peers = append(wireguardUpdate.Peers, peer)
					node.programmedInWireguard = true
				}
			} else if node.programmedInWireguard {
				// This node is programmed in wireguard and it should not be. Add a delta delete.
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
			nodenames := w.publicKeyToNodeNames[item.(wgtypes.Key)]
			if nodenames == nil {
				return nil
			}
			nodenames.Iter(func(nodename interface{}) error {
				node := w.nodes[nodename.(string)]
				if node == nil || node.programmedInWireguard == w.shouldProgramWireguardPeer(node) {
					// The node programming matches the expected value, so nothing to do.
					return nil
				} else if node.programmedInWireguard {
					// The node is programmed and shouldn't be. Add a delta delete.
					wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
						Remove:    true,
						PublicKey: node.publicKey,
					})
					node.programmedInWireguard = false
				} else {
					// The node is not programmed and should be.  Add a delta create.
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
		return &wireguardUpdate
	}
	return nil
}

// constructWireguardDeltaForResync checks the wireguard configuration matches the cached data and creates a delta
// update to correct any discrepancies.
func (w *Wireguard) constructWireguardDeltaForResync() (wgtypes.Key, *wgtypes.Config, error) {
	// Get the wireguard client
	client, err := w.getWireguardClient()
	if err != nil {
		w.logCxt.Errorf("error creating wireguard client: %v", err)
		return zeroKey, nil, err
	}

	// Get the wireguard device configuration.
	device, err := client.Device(w.config.InterfaceName)
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

		w.logCxt.Debugf("Checking allowed CIDRs for nodeData %s (key %v)", node, key)
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
					w.logCxt.Debug("Unexpected CIDR configured: %s", cidr)
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
func (w *Wireguard) ensureLink() (bool, error) {
	client, err := w.getNetlinkClient()
	if err != nil {
		w.logCxt.Errorf("error obtaining link client", err)
		return false, err
	}

	link, err := client.LinkByName(w.config.InterfaceName)
	if os.IsNotExist(err) {
		// Create the wireguard device.
		w.logCxt.Info("Wireguard device needs to be created")
		attr := netlink.NewLinkAttrs()
		attr.Name = w.config.InterfaceName
		lwg := netlink.GenericLink{
			LinkAttrs: attr,
			LinkType:  wireguardType,
		}

		if err := netlink.LinkAdd(&lwg); err != nil {
			w.logCxt.Errorf("error adding wireguard type link: %v", err)
			return false, err
		}

		link, err = netlink.LinkByName(w.config.InterfaceName)
		if err != nil {
			w.logCxt.Errorf("error querying wireguard device: %v", err)
			return false, err
		}

		w.logCxt.Info("Created wireguard device")
	} else if err != nil {
		w.logCxt.Errorf("unable to determine if wireguard device exists: %v", err)
		return false, err
	}

	// If necessary, update the MTU and admin status of the device.
	w.logCxt.Debug("Wireguard device exists, checking settings")
	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if w.config.MTU != nil && oldMTU != *w.config.MTU {
		w.logCxt.WithField("oldMTU", oldMTU).Info("Wireguard device MTU needs to be updated")
		if err := client.LinkSetMTU(link, *w.config.MTU); err != nil {
			w.logCxt.WithError(err).Warn("failed to set tunnel device MTU")
			return false, err
		}
		w.logCxt.Info("Updated tunnel MTU")
	}
	if attrs.Flags&net.FlagUp == 0 {
		w.logCxt.WithField("flags", attrs.Flags).Info("Wireguard interface wasn't admin up, enabling it")
		if err := client.LinkSetUp(link); err != nil {
			w.logCxt.WithError(err).Warn("failed to set wireguard device up")
			return false, err
		}
		w.logCxt.Info("Set wireguard admin up")
	}

	// Ensure the interface IP is correct.
	if err := w.ensureLinkAddressV4(); err != nil {
		return false, err
	}

	// Track whether the interface is oper up or not. We halt programming when it is down.
	return attrs.OperState == netlink.OperUp, nil
}

// ensureNoLink checks that the wireguard link is not present.
func (w *Wireguard) ensureNoLink() error {
	client, err := w.getNetlinkClient()
	if err != nil {
		w.logCxt.Errorf("error obtaining link client", err)
		return err
	}

	link, err := client.LinkByName(w.config.InterfaceName)
	if err == nil {
		// Wireguard device exists.
		w.logCxt.Info("Wireguard is disabled, deleting device")
		if err := client.LinkDel(link); err != nil {
			w.logCxt.Errorf("error deleting wireguard type link: %v", err)
			return err
		}
		w.logCxt.Info("Deleted wireguard device")
	} else if os.IsNotExist(err) {
		w.logCxt.Debug("Wireguard is disabled and does not exist")
	} else if err != nil {
		w.logCxt.Errorf("unable to determine if wireguard device exists: %v", err)
		return err
	}
	return nil
}

// ensureLinkAddressV4 ensures the wireguard link to set to the required local IP address.  It removes any other
// addresses.
func (w *Wireguard) ensureLinkAddressV4() error {
	client, err := w.getNetlinkClient()
	if err != nil {
		w.logCxt.Errorf("error obtaining link client", err)
		return err
	}

	w.logCxt.Debug("Setting local IPv4 address on link.")
	link, err := client.LinkByName(w.config.InterfaceName)
	if err != nil {
		w.logCxt.WithError(err).Warning("Failed to get device")
		return err
	}

	addrs, err := client.AddrList(link, netlink.FAMILY_V4)
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
		if err := client.AddrDel(link, &oldAddr); err != nil {
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
		if err := client.AddrAdd(link, addr); err != nil {
			w.logCxt.WithError(err).WithField("addr", address).Warn("failed to add address")
			return err
		}
	}
	w.logCxt.Debug("Address set.")

	return nil
}

func (w *Wireguard) ensureRouteRule() error {
	// Add rule attributes.
	rule := netlink.NewRule()
	rule.Priority = w.config.RoutingRulePriority
	rule.Table = w.config.RoutingTableIndex
	rule.Mark = w.config.FirewallMark

	//TODO(rlb): List existing rules and check based on protocol
	// Ignore error if the rule already exists, making this call idempotent.
	if client, err := w.getNetlinkClient(); err != nil {
		return err
	} else if err := client.RuleAdd(rule); err != nil && !os.IsExist(err) {
		return err
	}
	w.logCxt.Debug("Added rule: %s", rule)

	return nil
}

func (w *Wireguard) ensureNoRouteRule() error {
	// Add rule attributes.
	rule := netlink.NewRule()
	rule.Priority = w.config.RoutingRulePriority
	rule.Table = w.config.RoutingTableIndex
	rule.Mark = w.config.FirewallMark

	//TODO(rlb): List existing rules and check based on protocol
	// Ignore error if the rule doesn't exist, making this call idempotent.
	if client, err := w.getNetlinkClient(); err != nil {
		return err
	} else if err := client.RuleDel(rule); err != nil && !os.IsNotExist(err) {
		return err
	}

	// log.Debugf("Deleted rule: %s", rule)
	return nil
}

// ensureDisabled ensures all calico-installed wireguard configuration is removed.
func (w *Wireguard) ensureDisabled() error {
	var err1, err2, err3 error

	wg := sync.WaitGroup{}

	wg.Add(3)
	go func() {
		err1 = w.ensureNoRouteRule()
		wg.Done()
	}()
	go func() {
		err2 = w.ensureNoLink()
		wg.Done()
	}()
	go func() {
		// The routetable configuration will be empty since we will not send updates, so applying this will remove the
		// old routes if so configured.
		err3 = w.routetable.Apply()
		wg.Done()
	}()
	wg.Wait()

	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	if err3 != nil {
		return err3
	}
	return nil
}

func (w *Wireguard) shouldRouteToWireguard(node *nodeData) bool {
	return w.shouldProgramWireguardPeer(node)
}

func (w *Wireguard) shouldProgramWireguardPeer(node *nodeData) bool {
	return node.ipv4EndpointAddr != nil && node.publicKey != zeroKey && w.publicKeyToNodeNames[node.publicKey].Len() == 1
}

func (w *Wireguard) getWireguardClient() (WireguardClient, error) {
	if w.cachedWireguardClient == nil {
		if w.numConsistentWireguardClientFailures >= maxConnFailures && w.numConsistentWireguardClientFailures%wireguardClientRetryInterval != 0 {
			// It is a valid condition that we cannot connect to the wireguard client, so just log.
			w.logCxt.WithField("numFailures", w.numConsistentWireguardClientFailures).Debug(
				"Repeatedly failed to connect to wireguard client.")
			return nil, WireguardNotSupported
		}
		w.logCxt.Info("Trying to connect to wireguard client")
		client, err := w.newWireguardClient()
		if err != nil {
			w.numConsistentWireguardClientFailures++
			w.logCxt.WithField("numFailures", w.numConsistentWireguardClientFailures).Info(
				"Failed to connect to wireguard client: %v", err)
			return nil, err
		}
		w.cachedWireguardClient = client
	}
	if w.numConsistentWireguardClientFailures > 0 {
		w.logCxt.WithField("numFailures", w.numConsistentWireguardClientFailures).Info(
			"Connected to linkClient after previous failures.")
		w.numConsistentWireguardClientFailures = 0
	}
	return w.cachedWireguardClient, nil
}

func (w *Wireguard) closeWireguardClient() {
	if w.cachedWireguardClient == nil {
		return
	}
	if err := w.cachedWireguardClient.Close(); err != nil {
		w.logCxt.WithError(err).Error("Failed to close wireguard client, ignoring.")
	}
	w.cachedWireguardClient = nil
}

// getNetlinkClient returns a netlink client for managing device links.
func (w *Wireguard) getNetlinkClient() (NetlinkClient, error) {
	if w.cachedNetlinkClient == nil {
		// We do not expect the standard netlink client to fail, so panic after a set number of failed attempts.
		if w.numConsistentLinkClientFailures >= maxConnFailures {
			w.logCxt.WithField("numFailures", w.numConsistentLinkClientFailures).Panic(
				"Repeatedly failed to connect to netlink.")
		}
		w.logCxt.Info("Trying to connect to linkClient")
		client, err := w.newNetlinkClient()
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
	if err := w.cachedNetlinkClient.Close(); err != nil {
		w.logCxt.WithError(err).Error("Failed to close wireguard client, ignoring.")
	}
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

func (w *Wireguard) applyWireguardConfig(c *wgtypes.Config) error {
	if c == nil {
		return nil
	} else if wireguardClient, err := w.getWireguardClient(); err != nil {
		return err
	} else if err = wireguardClient.ConfigureDevice(w.config.InterfaceName, *c); err != nil {
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
