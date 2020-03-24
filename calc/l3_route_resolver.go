// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/set"
)

// L3RouteResolver is responsible for indexing IPAM blocks, IP pools and node information (either from the Node
// resource, if available, or from HostIP) and emitting basic routes containing the node's IP as next hop.
// Such routes are useful directly for BPF load balancing.  However, they are incomplete for VXLAN.
type L3RouteResolver struct {
	hostname  string
	callbacks routeCallbacks

	trie *RouteTrie

	// Store node metadata indexed by node name, and routes by the
	// block that contributed them.
	nodeNameToIPAddr       map[string]string
	nodeNameToNode         map[string]*apiv3.Node
	blockToRoutes          map[string]set.Set
	allPools               map[string]model.IPPool
	useNodeResourceUpdates bool
}

func NewL3RouteResolver(hostname string, callbacks PipelineCallbacks, useNodeResourceUpdates bool) *L3RouteResolver {
	logrus.Info("Creating L3 route resolver")
	return &L3RouteResolver{
		hostname:               hostname,
		callbacks:              callbacks,
		nodeNameToIPAddr:       map[string]string{},
		nodeNameToNode:         map[string]*apiv3.Node{},
		blockToRoutes:          map[string]set.Set{},
		allPools:               map[string]model.IPPool{},
		useNodeResourceUpdates: useNodeResourceUpdates,
	}
}

func (c *L3RouteResolver) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	if c.useNodeResourceUpdates {
		logrus.Info("Registering L3 route resolver (node resources on)")
		allUpdDispatcher.Register(model.ResourceKey{}, c.OnResourceUpdate)
	} else {
		logrus.Info("Registering L3 route resolver (node resources off)")
		allUpdDispatcher.Register(model.HostIPKey{}, c.OnHostIPUpdate)
	}

	allUpdDispatcher.Register(model.BlockKey{}, c.OnBlockUpdate)
	allUpdDispatcher.Register(model.IPPoolKey{}, c.OnPoolUpdate)
}

func (c *L3RouteResolver) OnBlockUpdate(update api.Update) (_ bool) {
	// Update the routes map based on the provided block update.
	key := update.Key.String()

	deletes := set.New()
	adds := set.New()
	if update.Value != nil {
		// Block has been created or updated.
		// We don't allow multiple blocks with the same CIDR, so no need to check
		// for duplicates here. Look at the routes contributed by this block and determine if we
		// need to send any updates.
		newRoutes := c.routesFromBlock(key, update.Value.(*model.AllocationBlock))
		logrus.WithField("numRoutes", len(newRoutes)).Debug("IPAM block update")
		cachedRoutes, ok := c.blockToRoutes[key]
		if !ok {
			cachedRoutes = set.New()
			c.blockToRoutes[key] = cachedRoutes
		}

		// Now scan the old routes, looking for any that are no-longer associated with the block.
		// Remove no longer active routes from the cache and queue up deletions.
		cachedRoutes.Iter(func(item interface{}) error {
			r := item.(nodenameRoute)

			// For each existing route which is no longer present, we need to delete it.
			// Note: since r.Key() only contains the destination, we need to check equality too in case
			// the gateway has changed.
			if newRoute, ok := newRoutes[r.Key()]; ok && newRoute == r {
				// Exists, and we want it to - nothing to do.
				return nil
			}

			// Current route is not in new set - we need to withdraw the route, and also
			// remove it from internal state.
			deletes.Add(r)
			logrus.WithField("route", r).Debug("Found stale route")
			return set.RemoveItem
		})

		// Now scan the new routes, looking for additions.  Cache them and queue up adds.
		for _, r := range newRoutes {
			logCxt := logrus.WithField("newRoute", r)
			if cachedRoutes.Contains(r) {
				logCxt.Debug("Desired route already exists, skip")
				continue
			}

			logrus.WithField("route", r).Debug("Found new route")
			cachedRoutes.Add(r)
			adds.Add(r)
		}

		// At this point we've determined the correct diff to perform based on the block update.
		// Delete any routes which are gone for good, withdraw modified routes, and send updates for
		// new ones.
		deletes.Iter(func(item interface{}) error {
			nr := item.(nodenameRoute)
			c.trie.RemoveBlockRoute(nr.dst.(ip.V4CIDR))
			return nil
		})
		adds.Iter(func(item interface{}) error {
			nr := item.(nodenameRoute)
			c.trie.UpdateBlockRoute(nr.dst.(ip.V4CIDR), nr.nodeName)
			return nil
		})
	} else {
		// Block has been deleted. Clean up routes that were contributed by this block.
		logrus.WithField("update", update).Debug("IPAM block deleted")
		routes := c.blockToRoutes[key]
		if routes != nil {
			routes.Iter(func(item interface{}) error {
			nr := item.(nodenameRoute)
				c.trie.RemoveBlockRoute(nr.dst.(ip.V4CIDR))
				return nil
			})
		}
		delete(c.blockToRoutes, key)
	}
	return
}

func (c *L3RouteResolver) OnResourceUpdate(update api.Update) (_ bool) {
	resourceKey := update.Key.(model.ResourceKey)
	if resourceKey.Kind != apiv3.KindNode {
		return
	}

	nodeName := update.Key.(model.ResourceKey).Name
	logCxt := logrus.WithField("node", nodeName).WithField("update", update)
	logCxt.Debug("OnResourceUpdate triggered")
	if update.Value != nil && update.Value.(*apiv3.Node).Spec.BGP != nil {
		node := update.Value.(*apiv3.Node)
		bgp := node.Spec.BGP
		c.nodeNameToNode[nodeName] = node
		ipv4, _, err := cnet.ParseCIDROrIP(bgp.IPv4Address)
		if err != nil {
			logCxt.WithError(err).Error("couldn't parse ipv4 address from node bgp info")
			return
		}

		c.onNodeIPUpdate(nodeName, ipv4.String())
	} else {
		delete(c.nodeNameToNode, nodeName)
		c.onRemoveNode(nodeName)
	}

	return
}

// OnHostIPUpdate gets called whenever a node IP address changes. On an add/update,
// we need to check if there are routes which are now valid, and trigger programming
// of them to the data plane. On a delete, we need to withdraw any routes and VTEPs associated
// with the node.
func (c *L3RouteResolver) OnHostIPUpdate(update api.Update) (_ bool) {
	nodeName := update.Key.(model.HostIPKey).Hostname
	logrus.WithField("node", nodeName).Debug("OnHostIPUpdate triggered")

	if update.Value != nil {
		c.onNodeIPUpdate(nodeName, update.Value.(*cnet.IP).String())
	} else {
		c.onRemoveNode(nodeName)
	}
	return
}

func (c *L3RouteResolver) onNodeIPUpdate(nodeName string, newIP string) {
	logCxt := logrus.WithFields(logrus.Fields{"node": nodeName, "newIP": newIP})

	oldIP := c.nodeNameToIPAddr[nodeName]
	if oldIP == newIP {
		logCxt.Debug("IP update but IP is unchanged, ignoring")
		return
	}
	if oldIP != "" {

	}

	if newIP == "" {
		delete(c.nodeNameToIPAddr, nodeName)
	} else {
		c.nodeNameToIPAddr[nodeName] = newIP
	}
	c.markAllNodeRoutesDirty(nodeName)
}

func (c *L3RouteResolver) onRemoveNode(nodeName string) {
	c.onNodeIPUpdate(nodeName, "")
}

func (c *L3RouteResolver) markAllNodeRoutesDirty(nodeName string) {
	c.visitAllRoutes(func(route nodenameRoute) {
		if route.nodeName != nodeName {
			return
		}
		c.trie.dirtyCIDRs.Add(route.dst.(ip.V4CIDR))
	})
}

func (c *L3RouteResolver) markAllRoutesInCIDRDirty(cidr ip.V4CIDR) {
	c.visitAllRoutes(func(route nodenameRoute) {
		if !cidr.ContainsV4(route.dst.Addr().(ip.V4Addr)) {
			return
		}
		c.trie.dirtyCIDRs.Add(route.dst.(ip.V4CIDR))
	})
}

func (c *L3RouteResolver) visitAllRoutes(v func(route nodenameRoute)) {
	for _, routes := range c.blockToRoutes {
		routes.Iter(func(item interface{}) error {
			v(item.(nodenameRoute))
			return nil
		})
	}
}

// OnPoolUpdate gets called whenever an IP pool changes.
func (c *L3RouteResolver) OnPoolUpdate(update api.Update) (_ bool) {
	k := update.Key.(model.IPPoolKey)
	poolKey := k.String()
	oldPool, oldPoolExists := c.allPools[poolKey]
	oldPoolType := PoolTypeUnknown
	var poolCIDR ip.V4CIDR
	if oldPoolExists {
		// Need explicit oldPoolExists check so that we don't pass a zero-struct to poolTypeForPool.
		oldPoolType = c.poolTypeForPool(&oldPool)
		poolCIDR = ip.CIDRFromCalicoNet(oldPool.CIDR).(ip.V4CIDR)
	}
	var newPool *model.IPPool
	if update.Value != nil {
		newPool = update.Value.(*model.IPPool)
	}
	newPoolType := c.poolTypeForPool(newPool)

	if oldPoolType == newPoolType {
		logrus.WithField("poolType", newPoolType).Debug(
			"Ignoring change to IPPool that didn't change pool type.")
		return
	}

	logCxt := logrus.WithFields(logrus.Fields{"oldType": oldPoolType, "newType": newPoolType})

	if newPool != nil && newPoolType != PoolTypeUnknown {
		logCxt.Info("Pool is active")
		c.allPools[poolKey] = *newPool
		poolCIDR = ip.CIDRFromCalicoNet(newPool.CIDR).(ip.V4CIDR)
	} else {
		delete(c.allPools, poolKey)
	}

	c.markAllRoutesInCIDRDirty(poolCIDR)

	return
}

func (c *L3RouteResolver) containsRoute(pool model.IPPool, r nodenameRoute) bool {
	return pool.CIDR.Contains(r.dst.ToIPNet().IP)
}

// routeReady returns true if the route is ready to be sent to the data plane, and
// false otherwise.
func (c *L3RouteResolver) routeReady(r nodenameRoute) bool {
	logCxt := logrus.WithField("route", r)

	poolType := c.poolTypeForRoute(r)
	if poolType == PoolTypeUnknown {
		logCxt.Debug("Route not ready: Route's pool is not known")
		return false
	}

	gw := c.nodeNameToIPAddr[r.nodeName]
	if gw == "" {
		logCxt.Debug("Route not ready: No gateway yet for route, skip")
		return false
	}

	return true
}

type PoolType int

const (
	PoolTypeUnknown PoolType = iota
	PoolTypeNoEncap
	PoolTypeVXLAN
	PoolTypeVXLANCrossSubnet
	PoolTypeIPIP
	PoolTypeIPIPCrossSubnet
)

func (t PoolType) String() string {
	switch t {
	case PoolTypeUnknown:
		return "PoolTypeUnknown"
	case PoolTypeNoEncap:
		return "PoolTypeNoEncap"
	case PoolTypeVXLAN:
		return "PoolTypeVXLAN"
	case PoolTypeVXLANCrossSubnet:
		return "PoolTypeVXLANCrossSubnet"
	case PoolTypeIPIP:
		return "PoolTypeIPIP"
	case PoolTypeIPIPCrossSubnet:
		return "PoolTypeIPIPCrossSubnet"
	default:
		return fmt.Sprintf("PoolType(%d)", int(t))
	}
}


func (c *L3RouteResolver) poolTypeForPool(pool *model.IPPool) PoolType {
	if pool == nil {
		return PoolTypeUnknown
	}
	if pool.VXLANMode == encap.CrossSubnet {
		return PoolTypeVXLANCrossSubnet
	}
	if pool.VXLANMode == encap.Always {
		return PoolTypeVXLAN
	}
	if pool.IPIPMode == encap.CrossSubnet {
		return PoolTypeIPIPCrossSubnet
	}
	if pool.IPIPMode == encap.Always {
		return PoolTypeIPIP
	}
	return PoolTypeNoEncap
}

// withdrawRouteIfActive will send a *proto.RouteRemove for the given route.
func (c *L3RouteResolver) withdrawRouteIfActive(r nodenameRoute) {
	if !c.trie.Get(r.dst.(ip.V4CIDR)).WasSent {
		logrus.WithField("route", r).Debug("Route was never sent, ignoring withdraw")
		return
	}
	logrus.WithField("route", r).Info("Sending route remove")
	c.callbacks.OnRouteRemove(proto.RouteType_WORKLOADS_NODE, r.dst.String())
	c.trie.SetRouteSent(r.dst.(ip.V4CIDR), false)
}

// sendRouteIfActive will send a *proto.RouteUpdate for the given route.
func (c *L3RouteResolver) sendRouteIfActive(r nodenameRoute) {
	if !c.routeReady(r) {
		logrus.WithField("route", r).Debug("Route wasn't ready, ignoring send")
		return
	}
	logrus.WithField("route", r).Info("Sending route update")
	c.callbacks.OnRouteUpdate(&proto.RouteUpdate{
		Type: proto.RouteType_WORKLOADS_NODE, // FIXME we throw away the route type, will want that if we rework VXLAN resolver to use our routes.
		Dst:  r.dst.String(),
		Node: r.nodeName,
		Gw:   c.nodeNameToIPAddr[r.nodeName],
	})
	c.trie.SetRouteSent(r.dst.(ip.V4CIDR), true)
}

// routesFromBlock returns a list of routes which should exist based on the provided
// allocation block.
func (c *L3RouteResolver) routesFromBlock(blockKey string, b *model.AllocationBlock) map[string]nodenameRoute {
	routes := make(map[string]nodenameRoute)

	for _, alloc := range b.NonAffineAllocations() {
		if alloc.Host == "" {
			logrus.WithField("IP", alloc.Addr).Warn(
				"Unable to create route for IP; the node it belongs to was not recorded in IPAM")
			continue
		}
		r := nodenameRoute{
			dst:      ip.CIDRFromNetIP(alloc.Addr.IP),
			nodeName: alloc.Host,
		}
		routes[r.Key()] = r
	}

	host := b.Host()
	if host == c.hostname {
		logrus.Debug("Skipping routes for local node")
	} else if host != "" {
		logrus.WithField("host", host).Debug("Block has a host, including block-via-host route")
		r := nodenameRoute{
			dst:      ip.CIDRFromCalicoNet(b.CIDR),
			nodeName: host,
		}
		routes[r.Key()] = r
	}

	return routes
}

// nodenameRoute is the L3RouteResolver's internal representation of a route.
type nodenameRoute struct {
	nodeName string
	dst      ip.CIDR
}

func (r nodenameRoute) Key() string {
	return r.dst.String()
}

func (r nodenameRoute) String() string {
	return fmt.Sprintf("hostnameRoute(dst: %s, node: %s)", r.dst.String(), r.nodeName)
}

// RouteTrie stores the information that we've gleaned from various, potentially overlapping sources.
//
// In general, we get updates about IPAM pools, blocks, nodes and individual pod IPs (extracted from the blocks).
// If none of those were allowed to overlap, things would be simple.  Unfortunately, we have to deal with:
//
// - Disabled IPAM pools that contain no blocks, which are used for tagging "external" IPs as safe destinations that
//   don't require SNAT.
// - IPAM pools that are the same size as their blocks and so share a CIDR.
// - IPAM blocks that are /32s so they overlap with the pod IP inside them (and potentially with a
//   misconfigured host IP).
// - Transient misconfigurations during a resync where we may see things out of order.
// - In future, /32s that we've learned from workload endpoints that are not contained within IP pools.
//
// In addition, the BPF program can only do a single lookup but it wants to know all the information about
// an IP, some of which is derived from the metadata further up the tree.  Means that, for each CIDR or IP that we
// care about, we want to maintain:
//
// - The next hop (for /32s and blocks).
// - The type of IP pool that it's inside of (or none).
// - Whether the IP pool have NAT-outgoing turned on or not.
//
// Approach: for each CIDR in the trie, we store a RouteInfo, which has fields for tracking the pool, block and
// next hop.  All updates are done via the updateCIDR method, which handles cleaning up RouteInfo structs that are no
// longer needed.
//
// The RouteTrie maintains a set of dirty CIDRs.  When an IPAM pool is updated, all the CIDRs under it are marked dirty.
type RouteTrie struct {
	t ip.V4Trie
	dirtyCIDRs set.Set
}

func (r *RouteTrie) UpdatePool(cidr ip.V4CIDR, poolType PoolType) {
	changed := r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.PoolType = poolType
	})
	if !changed {
		return
	}
	r.t.Visit(func(c ip.V4CIDR, data interface{}) bool {
		if cidr.ContainsV4(c.Addr().(ip.V4Addr)) {
			r.dirtyCIDRs.Add(c)
		}
		return true
	})
}

func (r *RouteTrie) RemovePool(cidr ip.V4CIDR) {
	r.UpdatePool(cidr, PoolTypeUnknown)
}

func (r *RouteTrie) UpdateBlockRoute(cidr ip.V4CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.NodeName = nodeName
	})
}

func (r *RouteTrie) RemoveBlockRoute(cidr ip.V4CIDR) {
	r.UpdateBlockRoute(cidr, "")
}

func (r *RouteTrie) AddHost(cidr ip.V4CIDR) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.IsHost = true
	})
}

func (r *RouteTrie) RemoveHost(cidr ip.V4CIDR) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.IsHost = false
	})
}

func (r *RouteTrie) SetRouteSent(cidr ip.V4CIDR, sent bool) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.WasSent = sent
	})
}

func (r RouteTrie) updateCIDR(cidr ip.V4CIDR, updateFn func(info *RouteInfo)) bool {
	// Get the RouteInfo for the given CIDR and take a copy so we can compare.
	ri := r.Get(cidr)
	riCopy := ri

	// Apply the update, whatever that is.
	updateFn(&ri)

	// Check if the update was a no-op.
	if riCopy == ri {
		// Change was a no-op, ignore.
		return false
	}

	// Not a no-op; mark CIDR as dirty.
	r.dirtyCIDRs.Add(cidr)
	if ri.Empty() {
		// No longer have anything to track about this CIDR, clean it up.
		r.t.Delete(cidr)
		return true
	}
	r.t.Update(cidr, ri)
	return true
}

func (r RouteTrie) Get(cidr ip.V4CIDR) RouteInfo {
	ri := r.t.Get(cidr)
	if ri == nil {
		return RouteInfo{}
	}
	return ri.(RouteInfo)
}

type RouteInfo struct {
	PoolType PoolType // Only set if this CIDR represents an IP pool
	NodeName string   // Set for each route that comes from an IPAM block.
	IsHost   bool     // true if this is a host's own IP.
	WasSent  bool
}

// Empty returns true if the RouteInfo no longer has any useful information; I.e. the CIDR it represents
// is not a pool, block route or host.
func (r RouteInfo) Empty() bool {
	return r.PoolType == PoolTypeUnknown && r.NodeName == "" && !r.IsHost && !r.WasSent
}
