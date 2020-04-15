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

package routetable

import (
	"errors"
	"net"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/conntrack"
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	netlinkshim "github.com/projectcalico/felix/netlink"
	timeshim "github.com/projectcalico/felix/time"
	"github.com/projectcalico/libcalico-go/lib/set"
)

const (
	cleanupGracePeriod = 10 * time.Second
	maxConnFailures    = 3
)

var (
	GetFailed       = errors.New("netlink get operation failed")
	ConnectFailed   = errors.New("connect to netlink failed")
	ListFailed      = errors.New("netlink list operation failed")
	UpdateFailed    = errors.New("netlink update operation failed")
	IfaceNotPresent = errors.New("interface not present")
	IfaceDown       = errors.New("interface down")
	IfaceGrace      = errors.New("interface in cleanup grace period")

	ipV6LinkLocalCIDR = ip.MustParseCIDROrIP("fe80::/64")

	listIfaceTime = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_route_table_list_seconds",
		Help: "Time taken to list all the interfaces during a resync.",
	})
	perIfaceSyncTime = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_route_table_per_iface_sync_seconds",
		Help: "Time taken to sync each interface",
	})
)

func init() {
	prometheus.MustRegister(listIfaceTime, perIfaceSyncTime)
}

const (
	// Use this for targets with no outbound interface.
	InterfaceNone = "*NoOIF*"
)

type TargetType string

const (
	TargetTypeVXLAN     TargetType = "vxlan"
	TargetTypeNoEncap   TargetType = "noencap"
	TargetTypeBlackhole TargetType = "blackhole"
	TargetTypeProhibit  TargetType = "prohibit"
	TargetTypeThrow     TargetType = "throw"
)

const (
	maxApplyRetries = 2
)

type L2Target struct {
	// For VXLAN targets, this is the node's real IP address.
	IP ip.Addr

	// For VXLAN targets, this is the MAC address of the remote VTEP.
	VTEPMAC net.HardwareAddr

	// For VXLAN targets, this is the IP address of the remote VTEP.
	GW ip.Addr
}

type Target struct {
	Type    TargetType
	CIDR    ip.CIDR
	GW      ip.Addr
	DestMAC net.HardwareAddr
}

func (t Target) Equal(t2 Target) bool {
	return reflect.DeepEqual(t, t2)
}

func (t Target) RouteType() int {
	switch t.Type {
	case TargetTypeThrow:
		return syscall.RTN_THROW
	case TargetTypeBlackhole:
		return syscall.RTN_BLACKHOLE
	case TargetTypeProhibit:
		return syscall.RTN_PROHIBIT
	default:
		return syscall.RTN_UNICAST
	}
}

func (t Target) RouteScope() netlink.Scope {
	switch t.Type {
	case TargetTypeThrow:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeBlackhole:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeProhibit:
		return netlink.SCOPE_UNIVERSE
	default:
		return netlink.SCOPE_LINK
	}
}

type updateType byte

const (
	updateTypeFullResync updateType = iota
	updateTypeDelta
)

type RouteTable struct {
	logCxt *log.Entry

	ipVersion      uint8
	netlinkFamily  int
	netlinkTimeout time.Duration
	// numConsistentNetlinkFailures counts the number of repeated netlink connection failures.
	// reset on successful connection.
	numConsistentNetlinkFailures int
	// Current netlink handle, or nil if we need to reconnect.
	cachedNetlinkHandle netlinkshim.Netlink

	// Interface update tracking.
	reSync                bool
	ifaceNameToUpdateType map[string]updateType
	ifacePrefixRegexp     *regexp.Regexp
	includeNoInterface    bool

	ifaceNameToTargets             map[string]map[ip.CIDR]Target
	ifaceNameToL2Targets           map[string][]L2Target
	ifaceNameToFirstSeen           map[string]time.Time
	pendingIfaceNameToTargets      map[string][]Target
	pendingIfaceNameToDeltaTargets map[string]map[ip.CIDR]*Target
	pendingIfaceNameToL2Targets    map[string][]L2Target

	pendingConntrackCleanups map[ip.Addr]chan struct{}

	// Whether this route table is managing vxlan routes.
	vxlan bool

	deviceRouteSourceAddress net.IP

	deviceRouteProtocol  int
	removeExternalRoutes bool

	// The route table index. A value of 0 defaults to the main table.
	tableIndex int

	// Testing shims, swapped with mock versions for UT
	newNetlinkHandle  func() (netlinkshim.Netlink, error)
	addStaticARPEntry func(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error
	conntrack         conntrackIface
	time              timeshim.Time
}

func New(
	interfaceRegexes []string,
	ipVersion uint8,
	vxlan bool,
	netlinkTimeout time.Duration,
	deviceRouteSourceAddress net.IP,
	deviceRouteProtocol int,
	removeExternalRoutes bool,
	tableIndex int,
) *RouteTable {
	return NewWithShims(
		interfaceRegexes,
		ipVersion,
		netlinkshim.NewRealNetlink,
		vxlan,
		netlinkTimeout,
		addStaticARPEntry,
		conntrack.New(),
		timeshim.NewRealTime(),
		deviceRouteSourceAddress,
		deviceRouteProtocol,
		removeExternalRoutes,
		tableIndex,
	)
}

// NewWithShims is a test constructor, which allows netlink, arp and time to be replaced by shims.
func NewWithShims(
	interfaceRegexes []string,
	ipVersion uint8,
	newNetlinkHandle func() (netlinkshim.Netlink, error),
	vxlan bool,
	netlinkTimeout time.Duration,
	addStaticARPEntry func(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error,
	conntrack conntrackIface,
	timeShim timeshim.Time,
	deviceRouteSourceAddress net.IP,
	deviceRouteProtocol int,
	removeExternalRoutes bool,
	tableIndex int,
) *RouteTable {
	var regexpParts []string
	includeNoOIF := false
	for _, interfaceRegex := range interfaceRegexes {
		if interfaceRegex == InterfaceNone {
			includeNoOIF = true
		} else {
			regexpParts = append(regexpParts, interfaceRegex)
		}
	}

	ifaceNamePattern := strings.Join(regexpParts, "|")
	log.WithField("regex", ifaceNamePattern).Info("Calculated interface name regexp")

	family := netlink.FAMILY_V4
	if ipVersion == 6 {
		family = netlink.FAMILY_V6
	} else if ipVersion != 4 {
		log.WithField("ipVersion", ipVersion).Panic("Unknown IP version")
	}

	return &RouteTable{
		logCxt: log.WithFields(log.Fields{
			"ipVersion": ipVersion,
		}),
		ipVersion:                      ipVersion,
		netlinkFamily:                  family,
		ifacePrefixRegexp:              regexp.MustCompile(ifaceNamePattern),
		includeNoInterface:             includeNoOIF,
		ifaceNameToTargets:             map[string]map[ip.CIDR]Target{},
		ifaceNameToL2Targets:           map[string][]L2Target{},
		ifaceNameToFirstSeen:           map[string]time.Time{},
		pendingIfaceNameToTargets:      map[string][]Target{},
		pendingIfaceNameToDeltaTargets: map[string]map[ip.CIDR]*Target{},
		pendingIfaceNameToL2Targets:    map[string][]L2Target{},
		reSync:                         true,
		ifaceNameToUpdateType:          map[string]updateType{},
		pendingConntrackCleanups:       map[ip.Addr]chan struct{}{},
		newNetlinkHandle:               newNetlinkHandle,
		netlinkTimeout:                 netlinkTimeout,
		addStaticARPEntry:              addStaticARPEntry,
		conntrack:                      conntrack,
		time:                           timeShim,
		vxlan:                          vxlan,
		deviceRouteSourceAddress:       deviceRouteSourceAddress,
		deviceRouteProtocol:            deviceRouteProtocol,
		removeExternalRoutes:           removeExternalRoutes,
		tableIndex:                     tableIndex,
	}
}

func (r *RouteTable) OnIfaceStateChanged(ifaceName string, state ifacemonitor.State) {
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	if !r.ifacePrefixRegexp.MatchString(ifaceName) {
		logCxt.Debug("Ignoring interface state change, not a Calico interface.")
		return
	}
	if state == ifacemonitor.StateUp {
		logCxt.Debug("Interface up, marking for route sync")
		r.ifaceNameToUpdateType[ifaceName] = updateTypeFullResync
		r.onIfaceSeen(ifaceName)
	}
}

func (r *RouteTable) onIfaceSeen(ifaceName string) {
	if _, ok := r.ifaceNameToFirstSeen[ifaceName]; ok {
		return
	}
	r.ifaceNameToFirstSeen[ifaceName] = r.time.Now()
}

// markIfaceForUpdate marks an interface update is required. This is either a delta update from a route
// set, update, or remove, or a full resync triggered from start-up processing, QueueResync or a previous failed update.
func (r *RouteTable) markIfaceForUpdate(ifaceName string, resync bool) {
	if resync {
		// This is a full resync so flag as such.
		r.ifaceNameToUpdateType[ifaceName] = updateTypeFullResync
	} else if _, ok := r.ifaceNameToUpdateType[ifaceName]; !ok {
		// This is not a full resync - set the update status if not already set (because we don't want to "downgrade"
		// a full-resync to a delta update).
		r.ifaceNameToUpdateType[ifaceName] = updateTypeDelta
	}
}

// SetRoutes sets the full set of targets for the specified interface. This clears any delta changes that were
// previously configured.
func (r *RouteTable) SetRoutes(ifaceName string, targets []Target) {
	// Store the routes.  Remove any delta routes since this is a full set of routes.
	r.pendingIfaceNameToTargets[ifaceName] = targets
	delete(r.pendingIfaceNameToDeltaTargets, ifaceName)
}

// RouteUpdate updates the route keyed off the target CIDR. These deltas will be applied to any routes set using
// SetRoute.
func (r *RouteTable) RouteUpdate(ifaceName string, target Target) {
	if r.pendingIfaceNameToDeltaTargets[ifaceName] == nil {
		r.pendingIfaceNameToDeltaTargets[ifaceName] = map[ip.CIDR]*Target{}
	}
	r.pendingIfaceNameToDeltaTargets[ifaceName][target.CIDR] = &target
	r.markIfaceForUpdate(ifaceName, false)
}

// RouteRemove removes the route with the specified CIDR. These deltas will be applied to any routes set using
// SetRoute.
func (r *RouteTable) RouteRemove(ifaceName string, cidr ip.CIDR) {
	if r.pendingIfaceNameToDeltaTargets[ifaceName] == nil {
		r.pendingIfaceNameToDeltaTargets[ifaceName] = map[ip.CIDR]*Target{}
	}
	r.pendingIfaceNameToDeltaTargets[ifaceName][cidr] = nil
	r.markIfaceForUpdate(ifaceName, false)
}

func (r *RouteTable) SetL2Routes(ifaceName string, targets []L2Target) {
	r.pendingIfaceNameToL2Targets[ifaceName] = targets
	r.markIfaceForUpdate(ifaceName, false)
}

func (r *RouteTable) QueueResync() {
	r.logCxt.Info("Queueing a resync of routing table.")
	r.reSync = true
}

func (r *RouteTable) getNetlinkHandle() (netlinkshim.Netlink, error) {
	if r.cachedNetlinkHandle == nil {
		if r.numConsistentNetlinkFailures >= maxConnFailures {
			log.WithField("numFailures", r.numConsistentNetlinkFailures).Panic(
				"Repeatedly failed to connect to netlink.")
		}
		log.Info("Trying to connect to netlink")
		nlHandle, err := r.newNetlinkHandle()
		if err != nil {
			r.numConsistentNetlinkFailures++
			log.WithError(err).WithField("numFailures", r.numConsistentNetlinkFailures).Error(
				"Failed to connect to netlink")
			return nil, err
		}
		err = nlHandle.SetSocketTimeout(r.netlinkTimeout)
		if err != nil {
			r.numConsistentNetlinkFailures++
			log.WithError(err).WithField("numFailures", r.numConsistentNetlinkFailures).Error(
				"Failed to set netlink timeout")
			nlHandle.Delete()
			return nil, err
		}
		r.cachedNetlinkHandle = nlHandle
	}
	if r.numConsistentNetlinkFailures > 0 {
		log.WithField("numFailures", r.numConsistentNetlinkFailures).Info(
			"Connected to netlink after previous failures.")
		r.numConsistentNetlinkFailures = 0
	}
	return r.cachedNetlinkHandle, nil
}

func (r *RouteTable) closeNetlinkHandle() {
	if r.cachedNetlinkHandle == nil {
		return
	}
	r.cachedNetlinkHandle.Delete()
	r.cachedNetlinkHandle = nil
}

func (r *RouteTable) Apply() error {
	if r.reSync {
		listStartTime := time.Now()

		nl, err := r.getNetlinkHandle()
		if err != nil {
			r.logCxt.WithError(err).Error("Failed to connect to netlink, retrying...")
			return ConnectFailed
		}
		links, err := nl.LinkList()
		if err != nil {
			r.logCxt.WithError(err).Error("Failed to list interfaces, retrying...")
			r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.
			return ListFailed
		}
		// Clear the dirty set; there's no point trying to update non-existent interfaces.
		r.ifaceNameToUpdateType = map[string]updateType{}
		for _, link := range links {
			attrs := link.Attrs()
			if attrs == nil {
				continue
			}
			ifaceName := attrs.Name
			if r.ifacePrefixRegexp.MatchString(ifaceName) {
				r.logCxt.WithField("ifaceName", ifaceName).Debug(
					"Resync: found calico-owned interface")
				r.markIfaceForUpdate(ifaceName, true)
				r.onIfaceSeen(ifaceName)
			}
		}
		// Clean up first-seen timestamps for old interfaces.
		// Resyncs happen periodically, so the amount of memory leaked to old
		// first seen timestamps is small.
		for name, firstSeen := range r.ifaceNameToFirstSeen {
			if _, ok := r.ifaceNameToUpdateType[name]; ok {
				// Interface still present.
				continue
			}
			if r.time.Since(firstSeen) < cleanupGracePeriod {
				// Interface first seen recently.
				continue
			}
			log.WithField("ifaceName", name).Debug(
				"Cleaning up timestamp for removed interface.")
			delete(r.ifaceNameToFirstSeen, name)
		}

		// If we are managing no-OIF routes then add that to our dirty set.
		if r.includeNoInterface {
			log.Debug("Flag no OIF for re-sync")
			r.markIfaceForUpdate(InterfaceNone, false)
		}

		r.reSync = false
		listIfaceTime.Observe(r.time.Since(listStartTime).Seconds())
	}

	graceIfaces := 0
ifaceLoop:
	for ifaceName, ia := range r.ifaceNameToUpdateType {
		logCxt := r.logCxt.WithField("ifaceName", ifaceName)
		fullResync := ia == updateTypeFullResync
		for retry := 0; retry < maxApplyRetries; retry++ {
			var err error
			if r.vxlan {
				// Sync L2 routes first.
				err = r.syncL2RoutesForLink(ifaceName)
			}
			if err == nil {
				// No errors syncing L2, sync L3 routes.
				err = r.syncRoutesForLink(ifaceName, fullResync)
			}

			// Handle errors from syncing either L2 or L3 routes.
			switch err {
			case nil:
				logCxt.Debug("Synchronised routes on interface")
				delete(r.ifaceNameToUpdateType, ifaceName)
				continue ifaceLoop
			case IfaceNotPresent:
				logCxt.Info("Interface missing, will retry if it appears.")
				delete(r.ifaceNameToUpdateType, ifaceName)
				continue ifaceLoop
			case IfaceDown:
				logCxt.Info("Interface down, will retry if it goes up.")
				delete(r.ifaceNameToUpdateType, ifaceName)
				continue ifaceLoop
			case IfaceGrace:
				logCxt.Info("Interface in cleanup grace period, will retry after.")
				graceIfaces++
				continue ifaceLoop
			}

			// We failed to sync the routes, next try perform a full resync.
			logCxt.WithError(err).Warn("Failed to synchronise routes.")
			fullResync = true
		}

		// The interface might be flapping or being deleted. Flag that it will require a full re-sync
		logCxt.Warn("Failed to sync routes to interface even after retries. " +
			"Leaving it dirty, requiring a full sync.")
		r.markIfaceForUpdate(ifaceName, true)
	}

	r.cleanUpPendingConntrackDeletions()

	// Don't return a failure if there are only interfaces in the cleanup grace period.
	// They'll be retried on the next invocation (the route refresh timer), and we mustn't
	// count them as Sync Errors.
	if len(r.ifaceNameToUpdateType) > graceIfaces {
		r.logCxt.Warn("Some interfaces still out-of sync.")
		return UpdateFailed
	}

	return nil
}

func (r *RouteTable) ensureL2Dataplane(linkAttrs *netlink.LinkAttrs, target L2Target) error {
	// For each L2 entry we need to program, program it.
	// Add a static ARP entry.
	a := &netlink.Neigh{
		LinkIndex:    linkAttrs.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           target.GW.AsNetIP(),
		HardwareAddr: target.VTEPMAC,
	}
	if err := netlink.NeighSet(a); err != nil {
		return err
	}
	log.WithField("entry", a).Debug("Programmed ARP")

	// Add a FDB entry for this neighbor.
	n := &netlink.Neigh{
		LinkIndex:    linkAttrs.Index,
		State:        netlink.NUD_PERMANENT,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           target.IP.AsNetIP(),
		HardwareAddr: target.VTEPMAC,
	}
	if err := netlink.NeighSet(n); err != nil {
		return err
	}
	log.WithField("entry", n).Debug("Programmed FDB")
	return nil
}

func (r *RouteTable) syncRoutesForLink(ifaceName string, fullSync bool) error {
	startTime := time.Now()
	defer func() {
		perIfaceSyncTime.Observe(r.time.Since(startTime).Seconds())
	}()
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	logCxt.Debug("Syncing interface routes")

	// If this is a modify or delete, grab a copy of the existing targets so we can clean up
	// conntrack entries even if the routes have been removed.  We'll remove any still-required
	// CIDRs from this set below.  We don't apply the grace period to this calculation because
	// it only removes routes that the datamodel previously said were there and then were
	// removed.  In that case, we know we're up to date.n

	// Determine the set of deleted, created and current targets
	currentCIDRsToTarget := r.ifaceNameToTargets[ifaceName]
	deletedCIDRsToTarget := map[ip.CIDR]Target{}
	createdCIDRsTarget := map[ip.CIDR]Target{}
	updatedCIDRsToTarget := currentCIDRsToTarget

	// Start with any complete target snapshots.
	if newTargets, ok := r.pendingIfaceNameToTargets[ifaceName]; ok {
		// Reset the expected CIDRs and construct from the new set.
		updatedCIDRsToTarget = map[ip.CIDR]Target{}
		logCxt.Debug("Have updated targets.")

		for cidr, target := range currentCIDRsToTarget {
			deletedCIDRsToTarget[cidr] = target
		}
		for _, target := range newTargets {
			if current, ok := currentCIDRsToTarget[target.CIDR]; ok && current.Equal(target) {
				// Entry is unchanged.  Remove from the deleted CIDRs.
				log.Debugf("Expected target unchanged for CIDR: %v", target.CIDR)
				delete(deletedCIDRsToTarget, target.CIDR)
			} else {
				// Entry has either been modified or been created. If modified then we'll keep the delete followed by a
				// create.
				log.Debugf("New target for CIDR: %v", target.CIDR)
				createdCIDRsTarget[target.CIDR] = target
			}
			updatedCIDRsToTarget[target.CIDR] = target
		}

		// Processed the snapshots so remove them.
		delete(r.pendingIfaceNameToTargets, ifaceName)
	}

	if updatedCIDRsToTarget == nil {
		// Police against there being no existing targets, but handling a route update.
		updatedCIDRsToTarget = map[ip.CIDR]Target{}
	}

	// Now apply deltas.
	if deltaTargets, ok := r.pendingIfaceNameToDeltaTargets[ifaceName]; ok {
		logCxt.Debug("Have delta targets.")

		for cidr, target := range deltaTargets {
			if current, ok := currentCIDRsToTarget[cidr]; ok {
				if target == nil {
					// Delta deletes a current entry. Make sure we delete the current entry and remove any entry to
					// create one.
					log.Debugf("Deleting target for CIDR: %v", cidr)
					deletedCIDRsToTarget[cidr] = current
					delete(createdCIDRsTarget, cidr)
					delete(updatedCIDRsToTarget, cidr)
				} else if target.Equal(current) {
					// Delta leaves the current entry unchanged, so remove any deleted and created entry that may exist.
					log.Debugf("Update leaves target unchanged for CIDR: %v", cidr)
					delete(deletedCIDRsToTarget, cidr)
					delete(createdCIDRsTarget, cidr)
					updatedCIDRsToTarget[cidr] = *target
				} else {
					// Delta changes existing entry.  Delete existing entry and create new entry.
					log.Debugf("Update changed target for CIDR: %v", cidr)
					deletedCIDRsToTarget[cidr] = current
					createdCIDRsTarget[cidr] = *target
					updatedCIDRsToTarget[cidr] = *target
				}
			} else if target != nil {
				// Delta adds a new entry.
				log.Debugf("Added new CIDR: %v", cidr)
				createdCIDRsTarget[cidr] = *target
				updatedCIDRsToTarget[cidr] = *target
			}
		}

		// Processed the deltas so remove them.
		delete(r.pendingIfaceNameToDeltaTargets, ifaceName)
	}

	// If there are no more expected targets for this interface then remove from the cache.
	if len(updatedCIDRsToTarget) == 0 {
		delete(r.ifaceNameToTargets, ifaceName)
	} else {
		r.ifaceNameToTargets[ifaceName] = updatedCIDRsToTarget
	}

	//
	// Don't remove any IPv6 link local entry.
	if r.ipVersion == 6 {
		delete(deletedCIDRsToTarget, ipV6LinkLocalCIDR)
	}

	// Any entry that we delete, we should remove the corresponding conntrack entries.
	defer func() {
		for cidr := range deletedCIDRsToTarget {
			r.startConntrackDeletion(cidr.Addr())
		}
	}()

	// Try to get the link.  This may fail if it's been deleted out from under us.
	linkAttrs, err := r.getLinkAttributes(ifaceName)
	if err != nil {
		return err
	}

	if !fullSync {
		// If we aren't doing a full re-sync then attempt to apply deltas to the route table.
		logCxt.Debug("Perform a delta route sync")
		if err := r.deltaUpdateRoutesForLink(logCxt, linkAttrs, ifaceName, deletedCIDRsToTarget, createdCIDRsTarget); err != UpdateFailed {
			return err
		}
	}

	// We are either scheduled to do a full resync, or a previous update failed. In either case, attempt a full
	// resync of state.
	logCxt.Debugf("Perform a full route sync: %v %v", updatedCIDRsToTarget, deletedCIDRsToTarget)
	return r.fullSyncRoutesForLink(logCxt, linkAttrs, ifaceName, updatedCIDRsToTarget, deletedCIDRsToTarget)
}

func (r *RouteTable) createL3Route(linkAttrs *netlink.LinkAttrs, target Target) netlink.Route {
	var linkIndex int
	if linkAttrs != nil {
		linkIndex = linkAttrs.Index
	}
	cidr := target.CIDR
	ipNet := cidr.ToIPNet()
	route := netlink.Route{
		LinkIndex: linkIndex,
		Dst:       &ipNet,
		Type:      target.RouteType(),
		Protocol:  r.deviceRouteProtocol,
		Scope:     target.RouteScope(),
		Table:     r.tableIndex,
	}

	if r.deviceRouteSourceAddress != nil {
		route.Src = r.deviceRouteSourceAddress
	}

	if target.GW != nil {
		route.Gw = target.GW.AsNetIP()
	}

	if target.Type == TargetTypeVXLAN || target.Type == TargetTypeNoEncap {
		route.Scope = netlink.SCOPE_UNIVERSE
		route.SetFlag(syscall.RTNH_F_ONLINK)
	}

	return route
}

// fullSyncRoutesForLink performs a full resync of the routes by first listing current routes and correlating against
// the expected set.
func (r *RouteTable) fullSyncRoutesForLink(
	logCxt *log.Entry, linkAttrs *netlink.LinkAttrs, ifaceName string,
	expectedCIDRsToTarget, deleted map[ip.CIDR]Target,
) error {
	nl, err := r.getNetlinkHandle()
	if err != nil {
		logCxt.Debug("Failed to connect to netlink")
		return ConnectFailed
	}

	// In order to allow Calico to run without Felix in an emergency, the CNI plugin pre-adds
	// the route to the interface.  To avoid flapping the route when Felix sees the interface
	// before learning about the endpoint, we give each interface a grace period after we first
	// see it before we remove routes that we're not expecting.  Check whether the grace period
	// applies to this interface.
	ifaceInGracePeriod := r.time.Since(r.ifaceNameToFirstSeen[ifaceName]) < cleanupGracePeriod

	// Got the link; try to sync its routes.  Note: We used to check if the interface
	// was oper down before we tried to do the sync but that prevented us from removing
	// routes from an interface in some corner cases (such as being admin up but oper
	// down).
	routeFilter := &netlink.Route{
		Table: r.tableIndex,
	}
	routeFilterFlags := netlink.RT_FILTER_OIF
	if r.tableIndex != 0 {
		routeFilterFlags |= netlink.RT_FILTER_TABLE
	}
	if linkAttrs != nil {
		// Link attributes might be nil for the special "no-OIF" interface name.
		routeFilter.LinkIndex = linkAttrs.Index
	}
	oldRoutes, err := nl.RouteListFiltered(r.netlinkFamily, routeFilter, routeFilterFlags)
	if err != nil {
		// Filter the error so that we don't spam errors if the interface is being torn
		// down.
		filteredErr := r.filterErrorByIfaceState(ifaceName, err, ListFailed)
		if filteredErr == ListFailed {
			logCxt.WithError(err).Error("Error listing routes")
			r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.
		} else {
			logCxt.WithError(err).Info("Failed to list routes; interface down/gone.")
		}
		return filteredErr
	}

	// Track any CIDRs in the route table that should not have been programmed and are not covered by the set of
	// deleted CIDRs.
	oldCIDRs := set.New()
	defer oldCIDRs.Iter(func(item interface{}) error {
		// Remove any conntrack entries that should no longer be there.
		dest := item.(ip.CIDR)
		r.startConntrackDeletion(dest.Addr())
		return nil
	})

	alreadyCorrectCIDRs := set.New()
	updatesFailed := false
	leaveDirty := false
	for _, route := range oldRoutes {
		logCxt.Debugf("Processing route: %v %v %v", route.Table, route.LinkIndex, route.Dst)
		var dest ip.CIDR
		if route.Dst != nil {
			dest = ip.CIDRFromIPNet(route.Dst)
		}
		logCxt := logCxt.WithField("dest", dest)
		// Check if we should remove routes not added by us
		if !r.removeExternalRoutes && route.Protocol != r.deviceRouteProtocol {
			logCxt.Info("Syncing routes: not removing route as its not marked as Felix route")
			continue
		}

		expectedTarget, expectedTargetFound := expectedCIDRsToTarget[dest]
		routeExpected := expectedTargetFound || (r.ipVersion == 6 && dest == ipV6LinkLocalCIDR)
		var routeProblems []string
		if !routeExpected {
			routeProblems = append(routeProblems, "unexpected route")
		}
		if !r.deviceRouteSourceAddress.Equal(route.Src) {
			routeProblems = append(routeProblems, "incorrect source address")
		}
		if dest != ipV6LinkLocalCIDR {
			if r.deviceRouteProtocol != route.Protocol {
				routeProblems = append(routeProblems, "incorrect protocol")
			}
			if expectedTargetFound && expectedTarget.RouteType() != route.Type {
				routeProblems = append(routeProblems, "incorrect type")
			}
		}
		if len(routeProblems) == 0 {
			alreadyCorrectCIDRs.Add(dest)
			continue
		}
		gracePeriodApplies := ifaceInGracePeriod && !routeExpected && !r.vxlan
		if gracePeriodApplies {
			// Don't remove unexpected routes from interfaces created recently. VXLAN routes don't have a grace period.
			logCxt.Info("Syncing routes: found unexpected route; ignoring due to grace period.")
			leaveDirty = true
			continue
		}
		logCxt = logCxt.WithField("routeProblems", routeProblems)
		logCxt.Info("Syncing routes: removing old route.")
		if err := nl.RouteDel(&route); err != nil {
			// Probably a race with the interface being deleted.
			logCxt.WithError(err).Info("Route deletion failed, assuming someone got there first.")
			updatesFailed = true
		}
		if !routeExpected && dest != nil {
			if _, ok := deleted[dest]; !ok {
				// Collect any old route CIDRs that we find in the dataplane so we can remove their conntrack entries
				// later. Entries in the deleted set are handled elsewhere.
				oldCIDRs.Add(dest)
			}
		}
	}
	for cidr, target := range expectedCIDRsToTarget {
		if !alreadyCorrectCIDRs.Contains(cidr) {
			logCxt := logCxt.WithField("targetCIDR", cidr)
			logCxt.Info("Syncing routes: adding new route.")
			route := r.createL3Route(linkAttrs, target)

			// In case this IP is being re-used, wait for any previous conntrack entry
			// to be cleaned up.  (No-op if there are no pending deletes.)
			r.waitForPendingConntrackDeletion(cidr.Addr())
			if err := nl.RouteAdd(&route); err != nil {
				logCxt.WithError(err).Warn("Failed to add route")
				updatesFailed = true
			}
		}
		if r.ipVersion == 4 && target.DestMAC != nil {
			// TODO(smc) clean up/sync old ARP entries
			err := r.addStaticARPEntry(cidr, target.DestMAC, ifaceName)
			if err != nil {
				logCxt.WithError(err).Warn("Failed to set ARP entry")
				updatesFailed = true
			}
		}
	}

	if updatesFailed {
		r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.

		// Recheck whether the interface exists so we don't produce spammy logs during
		// interface removal.
		return r.filterErrorByIfaceState(ifaceName, UpdateFailed, UpdateFailed)
	}

	if leaveDirty {
		// Superfluous routes on a recently created interface.  We'll recheck later.
		return IfaceGrace
	}

	return nil
}

// deltaUpdateRoutesForLink performs deltas to the routing configuration. This does not perform a full resync, so
// handles more routes per interface better.
func (r *RouteTable) deltaUpdateRoutesForLink(
	logCxt *log.Entry, linkAttrs *netlink.LinkAttrs, ifaceName string,
	deletedCIDRsToTarget, createdCIDRsToTarget map[ip.CIDR]Target,
) error {
	nl, err := r.getNetlinkHandle()
	if err != nil {
		logCxt.Debug("Failed to connect to netlink")
		return ConnectFailed
	}

	// Delete routes followed by creates.
	updatesFailed := false
	for cidr, target := range deletedCIDRsToTarget {
		route := r.createL3Route(linkAttrs, target)

		// In case this IP is being re-used, wait for any previous conntrack entry
		// to be cleaned up.  (No-op if there are no pending deletes.)
		r.waitForPendingConntrackDeletion(cidr.Addr())
		if err := nl.RouteDel(&route); err != nil {
			logCxt.WithError(err).Warn("Failed to delete route")
			updatesFailed = true
		}
	}

	// Delete routes followed by creates.
	for cidr, target := range createdCIDRsToTarget {
		route := r.createL3Route(linkAttrs, target)

		// In case this IP is being re-used, wait for any previous conntrack entry
		// to be cleaned up.  (No-op if there are no pending deletes.)
		r.waitForPendingConntrackDeletion(cidr.Addr())
		if err := nl.RouteAdd(&route); err != nil {
			logCxt.WithError(err).Warn("Failed to add route")
			updatesFailed = true
		}
		if r.ipVersion == 4 && target.DestMAC != nil {
			// TODO(smc) clean up/sync old ARP entries
			err := r.addStaticARPEntry(cidr, target.DestMAC, ifaceName)
			if err != nil {
				logCxt.WithError(err).Warn("Failed to set ARP entry")
				updatesFailed = true
			}
		}
	}

	if updatesFailed {
		r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.

		// Recheck whether the interface exists so we don't produce spammy logs during
		// interface removal.
		return r.filterErrorByIfaceState(ifaceName, UpdateFailed, UpdateFailed)
	}

	return nil
}

func (r *RouteTable) syncL2RoutesForLink(ifaceName string) error {
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	logCxt.Debug("Syncing interface L2 routes")
	if updatedTargets, ok := r.pendingIfaceNameToL2Targets[ifaceName]; ok {
		logCxt.Debug("Have updated targets.")
		if updatedTargets == nil {
			delete(r.ifaceNameToL2Targets, ifaceName)
		} else {
			r.ifaceNameToL2Targets[ifaceName] = updatedTargets
		}
		delete(r.pendingIfaceNameToL2Targets, ifaceName)
	}
	expectedTargets := r.ifaceNameToL2Targets[ifaceName]

	// Try to get the link attributes.  This may fail if it's been deleted out from under us.
	linkAttrs, err := r.getLinkAttributes(ifaceName)
	if err != nil {
		r.logCxt.WithError(err).Error("Failed to get link attributes")
		return err
	}

	// Build maps based on desired target state, used below to clean up
	// stale entries. Each L2 target results in an ARP entry as well as
	// a FDB entry.
	expectedARPEntries := map[string]net.HardwareAddr{}
	expectedFDBEntries := map[string]net.HardwareAddr{}
	for _, target := range expectedTargets {
		expectedARPEntries[target.GW.String()] = target.VTEPMAC
		expectedFDBEntries[target.IP.String()] = target.VTEPMAC
	}

	// Get the current set of neighbors on this interface.
	existingNeigh, err := netlink.NeighList(linkAttrs.Index, netlink.FAMILY_V4)
	if err != nil {
		return err
	}

	// For each existing neighbor, if it is not present in the expected set, then remove it.
	var updatesFailed bool
	for _, existing := range existingNeigh {
		if existing.Family == syscall.AF_BRIDGE {
			// FDB entries have family set to bridge.
			if _, ok := expectedFDBEntries[existing.IP.String()]; !ok {
				logCxt.WithField("neighbor", existing).Info("Removing old neighbor entry (FDB)")
				if err := netlink.NeighDel(&existing); err != nil {
					updatesFailed = true
					continue
				}
			}
		} else {
			if _, ok := expectedARPEntries[existing.IP.String()]; !ok {
				logCxt.WithField("neighbor", existing).Info("Removing old neighbor entry (ARP)")
				if err := netlink.NeighDel(&existing); err != nil {
					updatesFailed = true
					continue
				}
			}

		}
	}

	// For each expected target, ensure that it is programmed. If the value has changed since last programming, this
	// will update it.
	for _, target := range expectedTargets {
		if err = r.ensureL2Dataplane(linkAttrs, target); err != nil {
			logCxt.WithError(err).Warnf("Failed to sync L2 dataplane for interface")
			updatesFailed = true
			continue
		}
	}

	if updatesFailed {
		r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.

		// Recheck whether the interface exists so we don't produce spammy logs during
		// interface removal.
		return r.filterErrorByIfaceState(ifaceName, UpdateFailed, UpdateFailed)
	}

	return nil
}

// startConntrackDeletion starts the deletion of conntrack entries for the given CIDR in the background.  Pending
// deletions are tracked in the pendingConntrackCleanups map so we can block waiting for them later.
//
// It's important to do the conntrack deletions in the background because scanning the conntrack
// table is very slow if there are a lot of entries.  Previously, we did the deletion synchronously
// but that led to lengthy Apply() calls on the critical path.
func (r *RouteTable) startConntrackDeletion(ipAddr ip.Addr) {
	log.WithField("ip", ipAddr).Debug("Starting goroutine to delete conntrack entries")
	done := make(chan struct{})
	r.pendingConntrackCleanups[ipAddr] = done
	go func() {
		defer close(done)
		r.conntrack.RemoveConntrackFlows(r.ipVersion, ipAddr.AsNetIP())
		log.WithField("ip", ipAddr).Debug("Deleted conntrack entries")
	}()
}

// cleanUpPendingConntrackDeletions scans the pendingConntrackCleanups map for completed entries and removes them.
func (r *RouteTable) cleanUpPendingConntrackDeletions() {
	for ipAddr, c := range r.pendingConntrackCleanups {
		select {
		case <-c:
			log.WithField("ip", ipAddr).Debug(
				"Background goroutine finished deleting conntrack entries")
			delete(r.pendingConntrackCleanups, ipAddr)
		default:
			log.WithField("ip", ipAddr).Debug(
				"Background goroutine yet to finish deleting conntrack entries")
			continue
		}
	}
}

// waitForPendingConntrackDeletion waits for any pending conntrack deletions (if any) for the given IP to complete.
func (r *RouteTable) waitForPendingConntrackDeletion(ipAddr ip.Addr) {
	if c := r.pendingConntrackCleanups[ipAddr]; c != nil {
		log.WithField("ip", ipAddr).Info("Waiting for pending conntrack deletion to finish")
		<-c
		log.WithField("ip", ipAddr).Info("Done waiting for pending conntrack deletion to finish")
		delete(r.pendingConntrackCleanups, ipAddr)
	}
}

// filterErrorByIfaceState checks the current state of the interface; if it's down or gone, it
// returns IfaceDown or IfaceNotPresent, otherwise, it returns the given defaultErr.
func (r *RouteTable) filterErrorByIfaceState(ifaceName string, currentErr, defaultErr error) error {
	logCxt := r.logCxt.WithFields(log.Fields{"ifaceName": ifaceName, "error": currentErr})
	if ifaceName == InterfaceNone {
		// Short circuit the no-OIF interface name.
		logCxt.Info("No interface on route.")
		return defaultErr
	}

	if strings.Contains(currentErr.Error(), "not found") {
		// Current error already tells us that the link was not present.  If we re-check
		// the status in this case, we open a race where the interface gets created and
		// we log an error when we're about to re-trigger programming anyway.
		logCxt.Info("Failed to access interface because it doesn't exist.")
		return IfaceNotPresent
	}
	// If the current error wasn't clear, try to look up the interface to see if there's a
	// well-understood reason for the failure.
	nl, err := r.getNetlinkHandle()
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"ifaceName":  ifaceName,
			"currentErr": currentErr,
		}).Error("Failed to (re)connect to netlink while processing another error")
		return ConnectFailed
	}
	if link, err := nl.LinkByName(ifaceName); err == nil {
		// Link still exists.  Check if it's up.
		logCxt.WithField("link", link).Debug("Interface still exists")
		if link.Attrs().Flags&net.FlagUp != 0 {
			// Link exists and it's up, no reason that we expect to fail.
			logCxt.WithField("link", link).Warning(
				"Failed to access interface but it now appears to be up")
			return defaultErr
		} else {
			// Special case: Link exists and it's down.  Assume that's the problem.
			logCxt.WithField("link", link).Debug("Interface is down")
			return IfaceDown
		}
	} else if strings.Contains(err.Error(), "not found") {
		// Special case: Link no longer exists.
		logCxt.Info("Interface was deleted during operation, filtering error")
		return IfaceNotPresent
	} else {
		// Failed to list routes, then failed to check if interface exists.
		logCxt.WithError(err).Error("Failed to access interface after a failure")
		return defaultErr
	}
}

// getLinkAttributes returns the link attributes for the specified link name. This method returns nil if the
// interface name is the special "no-OIF" name.
func (r *RouteTable) getLinkAttributes(ifaceName string) (*netlink.LinkAttrs, error) {
	if ifaceName == InterfaceNone {
		// Short circuit the no-OIF interface name.
		return nil, nil
	}

	// Try to get the link.  This may fail if it's been deleted out from under us.
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)

	nl, err := r.getNetlinkHandle()
	if err != nil {
		r.logCxt.WithError(err).Error("Failed to connect to netlink, retrying...")
		return nil, ConnectFailed
	}

	link, err := nl.LinkByName(ifaceName)
	if err != nil {
		// Filter the error so that we don't spam errors if the interface is being torn
		// down.
		filteredErr := r.filterErrorByIfaceState(ifaceName, err, GetFailed)
		if filteredErr == GetFailed {
			logCxt.WithError(err).Error("Failed to get interface.")
			r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.
		} else {
			logCxt.WithError(err).Info("Failed to get interface; it's down/gone.")
		}
		return nil, filteredErr
	}
	return link.Attrs(), nil
}
