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
from calico.felix.actor import actor_event, Actor
from calico.felix.endpoint import LocalEndpoint

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
        self.endpoint_ids_by_tag = defaultdict(set)
        self.endpoint_ids_by_profile_id = defaultdict(set)

        # Child actors.
        self.local_endpoints_by_id = {}
        self.local_endpoints_by_iface_name = {}
        self.active_profiles = {}
        self.active_ipsets_by_tag = {}
        self.interfaces = {}

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
                _, tag_mapping = self._assign_tag_mapping(referenced_tags)
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
                nets = endpoint.get("ipv4_nets", [])  # FIXME IPv6
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
            created_tags, tag_mapping = self._assign_tag_mapping(required_tags)
            self._refresh_tags(created_tags)
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
        _log.info("Tags for profile %s updated", profile_id)
        old_tags = self.tags_by_id.get(profile_id, [])
        new_tags = tags or []
        self._process_tag_updates(profile_id, set(old_tags), set(new_tags))

        if tags is None:
            _log.info("Tags for profile %s deleted", profile_id)
            self.tags_by_id.pop(profile_id)
        else:
            self.tags_by_id[profile_id] = tags

    @actor_event
    def on_interface_update(self, name, iface_state):
        if iface_state:
            self.interfaces[name] = iface_state
        else:
            self.interfaces.pop(name)
        if name in self.local_endpoints_by_iface_name:
            ep = self.local_endpoints_by_iface_name[name]
            ep.on_interface_update(iface_state)

    @actor_event
    def on_endpoint_update(self, endpoint_id, endpoint):
        """
        Process an update to the given endpoint.  endpoint may be None if
        the endpoint was deleted.
        """
        _log.info("Endpoint update: %s", endpoint_id)

        old_endpoint = self.endpoints_by_id.get(endpoint_id, {})
        old_prof_id = old_endpoint.get("profile_id")
        old_tags = set(old_prof_id and self.tags_by_id[old_prof_id] or [])

        if endpoint is None:
            _log.info("Endpoint %s deleted", endpoint_id)
            if endpoint_id not in self.endpoints_by_id:
                _log.warn("Delete for unknown endpoint %s", endpoint_id)
                return
            # Update profile index.
            eps_for_profile = self.endpoint_ids_by_profile_id[old_prof_id]
            eps_for_profile.discard(endpoint_id)
            if not eps_for_profile:
                # Profile no longer has any endpoints using it, clean up
                # the index.
                _log.debug("Profile %s now unused", old_prof_id)
                del self.endpoint_ids_by_profile_id[old_prof_id]
                if old_prof_id in self.active_profiles:
                    # Profile active but no longer needed.  Clean it up.
                    self._discard_active_profile(old_prof_id)
                    # TODO: clean up unused ipsets.
            for tag in old_tags:
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
                self.local_endpoints_by_iface_name.pop(old_endpoint["name"])
                # TODO Remove this blocking call, needed to make sure we
                # don't recreate the endpoint before it has deleted its
                # chain.
                loc_ep.on_endpoint_update(endpoint)
            self.endpoints_by_id.pop(endpoint_id)
        else:
            new_prof_id = endpoint["profile_id"]
            new_tags = set(self.tags_by_id.get(new_prof_id, []))

            if endpoint["host"] == OUR_HOSTNAME:
                # Endpoint is local, make sure we have its profile.
                _log.debug("Endpoint update is for local endpoint.")
                profile_id = endpoint["profile_id"]
                ap = self._get_or_create_profile(profile_id)
                rules = self.rules_by_id.get(profile_id)
                # Make sure any required ipsets exist.  We'll update their
                # members below.
                required_tags = extract_tags_from_profile(rules)
                created_tags, tag_mapping = self._assign_tag_mapping(
                    required_tags)
                self._refresh_tags(created_tags)
                ap.on_profile_update(rules, tag_mapping, async=True)
                # Make sure the endpoint itself exists and update it.
                iface = endpoint["name"]
                ep = self._get_or_create_endpoint(iface,
                                                  endpoint_id=endpoint_id)
                ep.on_endpoint_update(endpoint, async=True)

            # Calculate impact on tags due to any change of profile or IP
            # address and queue updates to ipsets.
            # TODO: IPv6
            old_ips = set(old_endpoint.get("ipv4_nets", []))
            new_ips = set(endpoint.get("ipv4_nets", []))
            for removed_ip in old_ips - new_ips:
                for tag in old_tags:
                    if tag in self.active_ipsets_by_tag:
                        ipset = self.active_ipsets_by_tag[tag]
                        ipset.remove_member(removed_ip, async=True)
            for tag in old_tags - new_tags:
                if tag in self.active_ipsets_by_tag:
                    ipset = self.active_ipsets_by_tag[tag]
                    for ip in map(futils.net_to_ip,
                                  old_endpoint.get("ipv4_nets", [])):
                        ipset.remove_member(ip, async=True)
            for tag in new_tags:
                if tag in self.active_ipsets_by_tag:
                    ipset = self.active_ipsets_by_tag[tag]
                    for ip in map(futils.net_to_ip,
                                  endpoint.get("ipv4_nets", [])):
                        ipset.add_member(ip, async=True)

        _log.info("Endpoint update complete.")

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

    def _assign_tag_mapping(self, tags):
        created_tags = set()
        mapping = {}
        for tag in tags:
            created, ipset = self._get_or_create_ipset(tag)
            if created:
                created_tags.add(tag)
            mapping[tag] = ipset.name
        return created_tags, mapping

    def _get_or_create_ipset(self, tag):
        created = False
        if tag not in self.active_ipsets_by_tag:
            ipset = self.ipset_pool.allocate_ipset(tag)
            self.active_ipsets_by_tag[tag] = ipset
            created = True
        return created, self.active_ipsets_by_tag[tag]

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
        _log.debug("Endpoint IDs with this profile: %s", endpoint_ids)
        added_tags = new_tags - old_tags
        _log.debug("Profile %s added tags: %s", profile_id, added_tags)
        removed_tags = old_tags - new_tags
        _log.debug("Profile %s removed tags: %s", profile_id, removed_tags)
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
                        for ip in map(futils.net_to_ip,
                                      endpoint.get("ipv4_nets", [])):
                            # TODO: IPv6
                            if added:
                                ipset.add_member(ip, async=True)
                            else:
                                ipset.remove_member(ip, async=True)

    def _refresh_tags(self, tags):
        for tag in tags:
            _log.debug("Refreshing tag %s", tag)
            new_members = set()
            for ep_id in self.endpoint_ids_by_tag.get(tag, set()):
                ep = self.endpoints_by_id.get(ep_id, {})
                new_members.update(map(futils.net_to_ip, ep["ipv4_nets"]))
            self.active_ipsets_by_tag[tag].replace_members(new_members,
                                                           async=True)


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



