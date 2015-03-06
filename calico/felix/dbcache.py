# -*- coding: utf-8 -*-
# Copyright (c) 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
felix.dbcache
~~~~~~~~~~~~~

Our cache of the etcd database.
"""
from collections import defaultdict
import logging
import socket

from calico.felix import futils
from calico.felix.actor import actor_event, Actor, wait_and_check
from calico.felix.endpoint import get_endpoint_rules, LocalEndpoint
from calico.felix.frules import (program_profile_chains,
                                 CHAIN_FROM_ENDPOINT, CHAIN_TO_ENDPOINT,
                                 CHAIN_TO_PREFIX, CHAIN_FROM_PREFIX)


_log = logging.getLogger(__name__)


OUR_HOSTNAME = socket.gethostname()


class UpdateSequencer(Actor):
    def __init__(self, ipset_pool, v4_updater, v6_updater, dispatch_chains,
                 profile_manager):
        super(UpdateSequencer, self).__init__()

        # Peers/utility classes.
        self.ipset_pool = ipset_pool
        self.v4_updater = v4_updater
        self.v6_updater = v6_updater
        self.iptables_updaters = {
            4: v4_updater,
            6: v6_updater,
        }
        self.dispatch_chains = dispatch_chains
        self.profile_mgr = profile_manager

        # State.
        self.rules_by_id = {}
        self.tags_by_id = {}
        self.endpoints_by_id = {}

        # Indexes.
        # FIXME: need to use IDs here, can't hash a dict.
        self.endpoint_ids_by_tag = defaultdict(set)
        self.endpoint_ids_by_profile_id = defaultdict(set)

        # Child actors.
        self.local_endpoints_by_id = {}
        self.local_endpoints_by_iface_name = {}
        self.active_profiles = {}
        self.active_ipsets_by_tag = {}
        self.interfaces = {}

    def _get_or_create_profile(self, profile_id):
        if profile_id in self.active_profiles:
            ap = self.active_profiles[profile_id]
        else:
            ap = self.profile_mgr.get_profile_and_incref(profile_id)
            self.active_profiles[profile_id] = ap
        return ap

    def _discard_active_profile(self, profile_id):
        del self.active_profiles[profile_id]
        self.profile_mgr.return_profile(profile_id)

    @actor_event
    def apply_snapshot(self, rules_by_prof_id, tags_by_prof_id,
                       endpoints_by_id):
        """
        Replaces the whole cache state with the input.  Applies deltas vs the
        current active state.
        """

        # Spin through the endpoints, creating local endpoints, rules and
        # indexing tags.
        _log.info("Applying new database snapshot. Num rules: %s, tags: %s, "
                  "endpoints: %s", len(rules_by_prof_id), len(tags_by_prof_id),
                  len(endpoints_by_id))
        new_active_tags = set()
        new_endpoint_ids_by_tag = defaultdict(set)
        new_endpoint_ids_by_profile_id = defaultdict(set)
        new_active_profile_ids = set()
        new_local_endpoint_ids = set()
        for endpoint_id, endpoint in endpoints_by_id.iteritems():
            profile_id = endpoint["profile_id"]
            new_endpoint_ids_by_profile_id[profile_id].add(endpoint_id)
            if endpoint["host"] == OUR_HOSTNAME:
                new_local_endpoint_ids.add(endpoint_id)
                # Endpoint is local, make sure we have its profile.
                ap = self._get_or_create_profile(profile_id)
                rules = rules_by_prof_id.get(profile_id)
                new_active_profile_ids.add(profile_id)
                # Make sure any required ipsets exist.  We'll update their
                # members below.
                referenced_tags = extract_tags_from_profile(rules)
                tag_mapping = self._assign_tag_mapping(referenced_tags)
                ap.on_profile_update(rules, tag_mapping, async=True)
                new_active_tags.update(referenced_tags)
                # Make sure the endpoint itself exists and update it.
                iface = endpoint["name"]
                ep = self._get_or_create_endpoint(iface,
                                                  endpoint_id=endpoint_id)
                ep.on_endpoint_update(endpoint, async=True)
            for tag in tags_by_prof_id.get(profile_id, []):
                new_endpoint_ids_by_tag[tag].add(endpoint_id)

        # Now update the active tags.
        for tag, ipset in self.active_ipsets_by_tag.iteritems():
            new_members = set()
            for endpoint_id in new_endpoint_ids_by_tag[tag]:
                endpoint = endpoints_by_id[endpoint_id]
                nets = endpoint.get(["ipv4_nets"], [])  # FIXME IPv6
                new_members.update(map(futils.net_to_ip, nets))
            ipset.replace_members(new_members)

        # Clean up unused endpoints.
        for endpoint_id in (e for e in self.local_endpoints_by_id if
                            e not in new_local_endpoint_ids):
            ep = self.local_endpoints_by_id.pop(endpoint_id)
            # FIXME: Remove this blocking call. (Needed to stop us from
            # creating a new endpoint with the same ID before it has removed
            # its chain.)
            ep.on_endpoint_update(None)

        # Clean up unused profiles.
        for profile_id in (p for p in self.active_profiles.keys() if
                           p not in new_active_profile_ids):
            self._discard_active_profile(profile_id)

        # Clean up unused ipsets.
        for tag in (t for t in self.active_ipsets_by_tag
                    if t not in new_active_tags):
            ipset = self.active_ipsets_by_tag.pop(tag)
            self.ipset_pool.return_ipset(ipset)

        # Replace the database/indexes with the new snapshot.
        _log.info("Replacing state with new snapshot.")
        self.rules_by_id = rules_by_prof_id
        self.tags_by_id = tags_by_prof_id
        self.endpoints_by_id = endpoints_by_id
        self.endpoint_ids_by_tag = new_endpoint_ids_by_tag
        self.endpoint_ids_by_profile_id = new_endpoint_ids_by_profile_id

        _log.info("Finished applying snapshot.")

    @actor_event
    def on_rules_update(self, profile_id, rules):
        """
        Process an update to the rules of the given profile.
        :param dict[str,list[dict]] rules: New set of inbound/outbound rules
            or None if the rules have been deleted.
        """
        _log.info("Profile update: %s", profile_id)

        if profile_id in self.active_profiles:
            ap = self.active_profiles[profile_id]
            required_tags = extract_tags_from_profile(rules)
            tag_mapping = self._assign_tag_mapping(required_tags)
            ap.on_profile_update(rules, tag_mapping)
            # TODO: Clean up unused tags.

        if rules is None:
            self.rules_by_id.pop(profile_id)
            self._discard_active_profile(profile_id)

        _log.info("Profile update: %s complete", profile_id)

    @actor_event
    def on_tags_update(self, profile_id, tags):
        """
        Called when the given tag list has changed or been deleted.
        :param list[str] tags: List of tags for the given profile or None if
            deleted.
        """
        old_tags = self.tags_by_id.get(profile_id, set())
        new_tags = tags or set()
        self._process_tag_updates(profile_id, old_tags, new_tags)

        if tags is None:
            self.tags_by_id.pop(profile_id)

    @actor_event
    def on_interface_update(self, name, iface_state):
        if iface_state:
            self.interfaces[name] = iface_state
        else:
            self.interfaces.pop(name)
        if name in self.local_endpoints_by_iface_name:
            ep = self.local_endpoints_by_iface_name[name]
            ep.on_interface_update(iface_state)

    def _assign_tag_mapping(self, tags):
        mapping = {}
        for tag in tags:
            ipset = self._get_or_create_ipset(tag)
            mapping[tag] = ipset.name
        return mapping

    def _get_or_create_ipset(self, tag):
        if tag not in self.active_ipsets_by_tag:
            ipset = self.ipset_pool.allocate_ipset(tag)
            self.active_ipsets_by_tag[tag] = ipset
        return self.active_ipsets_by_tag[tag]

    def _get_or_create_endpoint(self, iface_name, endpoint_id=None):
        if iface_name not in self.local_endpoints_by_iface_name:
            ep = LocalEndpoint(self.iptables_updaters,
                               self.dispatch_chains,
                               self.profile_mgr).start()
            self.local_endpoints_by_iface_name[iface_name] = ep
            if iface_name in self.interfaces:
                _log.debug("Already know about interface %s", iface_name)
                ep.on_interface_update(self.interfaces[iface_name], async=True)
        else:
            ep = self.local_endpoints_by_iface_name[iface_name]
        if endpoint_id:
            self.local_endpoints_by_id[endpoint_id] = ep
        return ep

    def _process_tag_updates(self, profile_id, old_tags, new_tags):
        """
        Updates the active ipsets associated with the change in tags
        of the given profile ID.
        """
        endpoint_ids = self.endpoint_ids_by_profile_id.get(profile_id, set())
        added_tags = new_tags - old_tags
        removed_tags = old_tags - new_tags
        for added, upd_tags in [(True, added_tags), (False, removed_tags)]:
            for tag in upd_tags:
                if added:
                    self.endpoint_ids_by_tag[tag] |= endpoint_ids
                else:
                    self.endpoint_ids_by_tag[tag] -= endpoint_ids
                if tag in self.active_ipsets_by_tag:
                    # Tag is in-use, update its members.
                    ipset = self.active_ipsets_by_tag[tag]
                    for endpoint_id in endpoint_ids:
                        endpoint = self.endpoints_by_id[endpoint_id]
                        for ip in endpoint["ip_addresses"]:
                            if added:
                                ipset.add_member(ip, async=True)
                            else:
                                ipset.remove_member(ip, async=True)

    def _profile_active(self, profile_id):
        return profile_id in self.active_profile_ids

    def _ensure_profile_ipsets_exist(self, profile):
        for tag in extract_tags_from_profile(profile):
            self._get_or_create_ipset(tag)

    @actor_event
    def on_endpoint_update(self, endpoint_id, endpoint):
        """
        Process an update to the given endpoint.  endpoint may be None if
        the endpoint was deleted.
        """
        _log.info("Endpoint update: %s", endpoint_id)
        if endpoint is None:
            if endpoint_id in self.endpoints_by_id:
                old_endpoint = self.endpoints_by_id[endpoint_id]
                profile_id = old_endpoint["profile_id"]
                # Update profile index.
                eps_for_profile = self.endpoint_ids_by_profile_id[profile_id]
                eps_for_profile.discard(endpoint_id)
                if not eps_for_profile:
                    # Profile no longer has any endpoints using it, clean up
                    # the index.
                    del self.endpoint_ids_by_profile_id[profile_id]
                    if profile_id in self.active_profiles:
                        # Profile active but no longer needed.  Clean it up.
                        self._discard_active_profile(profile_id)
                        # TODO: clean up unused ipsets.
                tags = self.tags_by_id.get(profile_id, [])
                for tag in tags:
                    self.endpoint_ids_by_tag[tag].discard(endpoint_id)
                    if not self.endpoint_ids_by_tag[tag]:
                        del self.endpoint_ids_by_tag[tag]
                    if tag in self.active_ipsets_by_tag:
                        for ip in map(futils.net_to_ip,
                                      old_endpoint["ipv4_nets"]):
                            # TODO: IPv6
                            ipset = self.active_ipsets_by_tag[tag]
                            ipset.remove_member(ip, async=True)
                if endpoint_id in self.local_endpoints_by_id:
                    loc_ep = self.local_endpoints_by_id.pop(endpoint_id)
                    self.local_endpoints_by_iface_name.pop(endpoint["name"])
                    # TODO Remove this blocking call, needed to make sure we
                    # don't recreate the endpoint before it has deleted its
                    # chain.
                    loc_ep.on_endpoint_update(endpoint)
                self.endpoints_by_id.pop(endpoint_id)
        else:
            new_profile_id = endpoint["profile_id"]
            new_profile = self.rules_by_id[new_profile_id]
            new_tags = new_profile["tags"]
            old_ips_per_tag = defaultdict(set)

            if endpoint_id in self.endpoints_by_id:
                _log.debug("Update to existing endpoint %s.", endpoint_id)
                old_endpoint = self.endpoints_by_id[endpoint_id]
                if old_endpoint == endpoint:
                    _log.info("No change to endpoint, skipping.")
                    return
                old_profile_id = old_endpoint["profile_id"]
                old_profile = self.rules_by_id[old_profile_id]
                old_tags = old_profile["tags"]

                # Find the endpoint's previous contribution to the ipsets.
                for tag in old_tags:
                    old_ips_per_tag[tag].update(old_endpoint["ip_addresses"])
                    self.endpoint_ids_by_tag[tag].remove(endpoint_id)
                # Remove from the index, we'll fix up below.  No race,
                # we can't be interrupted.
                self.endpoint_ids_by_profile_id[old_profile_id].remove(
                    endpoint_id)
            else:
                # New endpoint, implicitly had no tags before.
                _log.info("New endpoint: %s", endpoint_id)
                old_tags = []
                old_profile_id = None

            # Figure out current contribution to tags.
            _log.debug("Need to sync tags.")
            new_ips_per_tag = defaultdict(set)
            for tag in new_tags:
                new_ips_per_tag[tag].update(endpoint["ip_addresses"])
                self.endpoint_ids_by_tag[tag].add(endpoint_id)

            # Diff the set of old vs new IP addresses and apply deltas.
            futures = []
            for tag in set(old_tags + new_tags):
                if tag not in self.active_ipsets_by_tag:
                    # ipset isn't in use on this host, skip.
                    continue
                ipset = self.active_ipsets_by_tag[tag]
                for ip in old_ips_per_tag[tag] - new_ips_per_tag[tag]:
                    _log.debug("Removing %s from ipset for %s", ip, tag)
                    f = ipset.remove_member(ip, async=True)
                    futures.append(f)
                for ip in new_ips_per_tag[tag] - old_ips_per_tag[tag]:
                    _log.debug("Adding %s to ipset for %s", ip, tag)
                    f = ipset.add_member(ip, async=True)
                    futures.append(f)
            wait_and_check(futures)

            self.endpoint_ids_by_profile_id[new_profile_id].add(endpoint_id)
            self.endpoints_by_id[endpoint_id] = endpoint

            if endpoint["host"] == OUR_HOSTNAME:
                # Create any missing ipsets.
                _log.info("Endpoint is local, checking profile.")
                self.local_endpoint_ids.add(endpoint_id)
                self._ensure_profile_ipsets_exist(new_profile)

                if new_profile_id not in self.active_profile_ids:
                    program_profile_chains(new_profile_id, new_profile)

                if old_profile_id and old_profile_id != new_profile_id:
                    # Old profile may be unused. Recalculate.
                    _log.debug("Recalculating active_profile_ids index.")
                    self.active_profile_ids = set()
                    for endpoint_id in self.local_endpoint_ids:
                        endpoint = self.endpoints_by_id[endpoint_id]
                        self.active_profile_ids.add(endpoint["profile_id"])
                    # TODO: GC unused chains

                chains, updates = get_endpoint_rules(
                    endpoint_id,
                    endpoint["name"],
                    4,
                    endpoint["ip_addresses"],
                    endpoint["mac"],
                    endpoint["profile_id"])
                updates += self.active_endpoint_updates()
                # TODO: IPv6
                self.v4_updater.apply_updates("filter", chains, updates)

        _log.info("Endpoint update complete.")

    def active_endpoint_updates(self):
        updates = [
            "--flush " + CHAIN_FROM_ENDPOINT,
            "--flush " + CHAIN_TO_ENDPOINT,
        ]
        for endpoint_id in self.local_endpoint_ids:
            endpoint = self.endpoints_by_id[endpoint_id]
            iface = endpoint["name"]
            to_chain_name = CHAIN_TO_PREFIX + endpoint_id
            from_chain_name = CHAIN_FROM_PREFIX + endpoint_id

            # Add rule to global chain to direct traffic to the
            # endpoint-specific one.
            updates.append("--append %s --out-interface %s --goto %s" %
                           (CHAIN_TO_ENDPOINT, iface, to_chain_name))
            updates.append("--append %s --in-interface %s --goto %s" %
                           (CHAIN_FROM_ENDPOINT, iface, from_chain_name))
            # FIXME: should we drop at end of this?
        return updates


def extract_tags_from_profile(profile):
    if profile is None:
        return set()
    tags = set()
    for in_or_out in ["inbound", "outbound"]:
        for rule in profile.get(in_or_out, []):
            tags.update(extract_tags_from_rule(rule))
    return tags


def extract_tags_from_rule(rule):
    return set([rule[key] for key in ["src_tag", "dst_tag"] if key in rule])



