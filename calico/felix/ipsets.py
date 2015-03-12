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
felix.ipsets
~~~~~~~~~~~~

IP sets management functions.
"""
from collections import defaultdict

import logging
from subprocess import CalledProcessError
from calico.felix import futils
from calico.felix.actor import Actor, actor_event, ReferenceManager
from gevent import subprocess
import re

_log = logging.getLogger(__name__)


class TagManager(ReferenceManager):
    def __init__(self, config, v4_updater, v6_updater):
        super(TagManager, self).__init__()

        # Peers/utility classes.
        self.config = config
        self.v4_updater = v4_updater
        self.v6_updater = v6_updater
        self.iptables_updaters = {
            4: v4_updater,
            6: v6_updater,
        }

        # State.
        self.tags_by_id = {}
        self.endpoints_by_id = {}

        # Indexes.
        self.endpoint_ids_by_tag = defaultdict(set)
        self.endpoint_ids_by_profile_id = defaultdict(set)

    def _create(self, tag_id):
        return IpsetUpdater(tag_id, "hash:ip")

    def _on_object_activated(self, tag_id, active_tag):
        new_members = set()
        for ep_id in self.endpoint_ids_by_tag.get(tag_id, set()):
            ep = self.endpoints_by_id.get(ep_id, {})
            # TODO: IPv6
            new_members.update(map(futils.net_to_ip, ep["ipv4_nets"]))
        # FIXME: Remove blocking call
        active_tag.replace_members(new_members, async=True)

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
            self.tags_by_id.pop(profile_id, None)
        else:
            self.tags_by_id[profile_id] = tags

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
                if self._is_active(tag):
                    # Tag is in-use, update its members.
                    ipset = self.objects_by_id[tag]
                    for endpoint_id in endpoint_ids:
                        endpoint = self.endpoints_by_id[endpoint_id]
                        for ip in map(futils.net_to_ip,
                                      endpoint.get("ipv4_nets", [])):
                            # TODO: IPv6
                            if added:
                                ipset.add_member(ip, async=True)
                            else:
                                ipset.remove_member(ip, async=True)

    @actor_event
    def on_endpoint_update(self, endpoint_id, endpoint):
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
            for tag in old_tags:
                self.endpoint_ids_by_tag[tag].discard(endpoint_id)
                if not self.endpoint_ids_by_tag[tag]:
                    del self.endpoint_ids_by_tag[tag]
                if self._is_active(tag):
                    for ip in map(futils.net_to_ip,
                                  old_endpoint["ipv4_nets"]):
                        # TODO: IPv6
                        ipset = self.objects_by_id[tag]
                        ipset.remove_member(ip, async=True)
            self.endpoints_by_id.pop(endpoint_id, None)
        else:
            _log.info("Endpoint %s update received.", endpoint_id)
            new_prof_id = endpoint["profile_id"]
            new_tags = set(self.tags_by_id.get(new_prof_id, []))

            # Calculate impact on tags due to any change of profile or IP
            # address and queue updates to ipsets.
            # TODO: IPv6
            old_ips = set(map(futils.net_to_ip,
                              old_endpoint.get("ipv4_nets", [])))
            new_ips = set(map(futils.net_to_ip, endpoint.get("ipv4_nets", [])))
            for removed_ip in old_ips - new_ips:
                for tag in old_tags:
                    if self._is_active(tag):
                        ipset = self.objects_by_id[tag]
                        ipset.remove_member(removed_ip, async=True)
            for tag in old_tags - new_tags:
                self.endpoint_ids_by_tag[tag].discard(endpoint_id)
                if self._is_active(tag):
                    ipset = self.objects_by_id[tag]
                    for ip in old_ips:
                        ipset.remove_member(ip, async=True)
            for tag in new_tags:
                self.endpoint_ids_by_tag[tag].add(endpoint_id)
                if self._is_active(tag):
                    ipset = self.objects_by_id[tag]
                    for ip in new_ips:
                        ipset.add_member(ip, async=True)

            self.endpoints_by_id[endpoint_id] = endpoint
            if old_prof_id:
                ids = self.endpoint_ids_by_profile_id[old_prof_id]
                ids.discard(endpoint_id)
                if not ids:
                    del self.endpoint_ids_by_profile_id[old_prof_id]
            self.endpoint_ids_by_profile_id[new_prof_id].add(endpoint_id)

        _log.info("Endpoint update complete.")


def tag_to_ipset_name(tag_name):
    assert re.match(r'^\w+$', tag_name), "Tags must be alphanumeric for now"
    return "calico-tag-" + tag_name


class IpsetUpdater(Actor):

    def __init__(self, name, set_type):
        super(IpsetUpdater, self).__init__()

        self.name = name
        self.set_type = set_type
        self.members = set()
        """Database state"""

        self.programmed_members = None
        """
        State loaded from ipset command.  None if we haven't loaded
        yet or the set doesn't exist.
        """

        self._load_from_ipset(async=True)

    @actor_event
    def replace_members(self, members):
        _log.info("Replacing members of ipset %s", self.name)
        assert isinstance(members, set), "Expected members to be a set"
        self.members = members
        self._sync_to_ipset()

    @actor_event
    def add_member(self, member):
        _log.info("Adding member %s to ipset %s", member, self.name)
        self.members.add(member)
        self._sync_to_ipset()

    @actor_event
    def remove_member(self, member):
        _log.info("Removing member %s from ipset %s", member, self.name)
        try:
            self.members.remove(member)
        except KeyError:
            _log.info("%s was not in ipset %s", member, self.name)
        else:
            self._sync_to_ipset()

    @actor_event
    def _load_from_ipset(self):
        try:
            output = subprocess.check_output(["ipset", "list", self.name])
        except CalledProcessError as cpe:
            if cpe.returncode == 1:
                # ipset doesn't exist.  TODO: better check?
                self.programmed_members = None
            else:
                raise
        else:
            # Output ends with:
            # Members:
            # <one member per line>
            lines = output.splitlines()
            self.programmed_members = set(lines[lines.index("Members:") + 1:])

    def _sync_to_ipset(self):
        if self.programmed_members is None:
            # We're only called after _load_from_ipset() so we know that the
            # ipset doesn't exist.
            subprocess.check_output(
                ["ipset", "create", self.name, self.set_type])
            self.programmed_members = set()
        _log.debug("Programmed members: %s", self.programmed_members)
        _log.debug("Desired members: %s", self.members)
        members_to_add = self.members - self.programmed_members
        _log.debug("Adding members: %s", members_to_add)
        for member in members_to_add:
            subprocess.check_output(["ipset", "add", self.name, member])
            self.programmed_members.add(member)
        members_to_remove = self.programmed_members - self.members
        _log.debug("Removing members: %s", members_to_remove)
        for member in members_to_remove:
            subprocess.check_output(["ipset", "del", self.name, member])
            self.programmed_members.remove(member)
        assert self.programmed_members == self.members


