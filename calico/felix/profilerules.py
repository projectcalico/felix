# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
felix.profilerules
~~~~~~~~~~~~

ProfileRules actor, handles local profile chains.
"""
import functools
import logging
import itertools
from calico.felix.actor import Actor, actor_event, wait_and_check
from calico.felix.frules import (profile_to_chain_name,
                                 rules_to_chain_rewrite_lines)
from calico.felix.refcount import ReferenceManager, RefCountedActor

_log = logging.getLogger(__name__)


_correlators = ("prof-%s" % i for  i in itertools.count())


class RulesManager(ReferenceManager):
    """
    Actor that manages the life cycle of ProfileRules objects.
    Users must ensure that they correctly pair calls to
    get_and_incref() and decref().

    This class ensures that rules chains are properly quiesced
    before their Actors are deleted.
    """
    def __init__(self, iptables_updaters, ipset_mgrs):
        super(RulesManager, self).__init__()
        self.iptables_updaters = iptables_updaters
        self.ipset_mgrs = ipset_mgrs
        self.rules_by_profile_id = {}

    def _create(self, profile_id):
        return ProfileRules(profile_id, self.iptables_updaters,
                             self.ipset_mgrs)

    def _on_object_activated(self, profile_id, active_profile):
        profile_or_none = self.rules_by_profile_id.get(profile_id)
        active_profile.on_profile_update(profile_or_none, async=True)

    @actor_event
    def apply_snapshot(self, rules_by_profile_id):
        missing_ids = set(self.rules_by_profile_id.keys())
        for profile_id, profile in rules_by_profile_id.iteritems():
            self.on_rules_update(profile_id, profile)  # Skips queue
            missing_ids.discard(profile_id)
            self._maybe_yield()
        for dead_profile_id in missing_ids:
            self.on_rules_update(dead_profile_id, None)

    @actor_event
    def on_rules_update(self, profile_id, profile):
        _log.debug("Processing update to %s", profile_id)
        if profile_id is not None:
            self.rules_by_profile_id[profile_id] = profile
        else:
            self.rules_by_profile_id.pop(profile_id, None)
        if self._is_starting_or_live(profile_id):
            ap = self.objects_by_id[profile_id]
            ap.on_profile_update(profile, async=True)


class ProfileRules(RefCountedActor):
    """
    Actor that owns the per-profile rules chains.
    """
    def __init__(self, profile_id, iptables_updaters, ipset_mgrs):
        super(ProfileRules, self).__init__()
        assert profile_id is not None
        self.id = profile_id
        self.ipset_mgrs = ipset_mgrs
        self._programmed = False
        self._iptables_updaters = iptables_updaters
        self._profile = None
        """:type dict: filled in by first update"""
        self._tag_to_ip_set_name = {4: {}, 6: {}}
        """:type dict[str, str]: current mapping from tag name to ipset name."""
        self.pending_ipset_correlators = {4: {}, 6: {}}
        self.pending_updates = {4: {}, 6: {}}
        self.pending_deletes = {4: {}, 6: {}}

    @actor_event
    def on_profile_update(self, profile):
        """
        Update the programmed iptables configuration with the new
        profile.  Returns after the update is present in the dataplane.
        """
        assert profile is None or profile["id"] == self.id

        old_tags = extract_tags_from_profile(self._profile)
        new_tags = extract_tags_from_profile(profile)

        removed_tags = old_tags - new_tags
        added_tags = new_tags - old_tags
        for ip_version, ipset_mgr in self.ipset_mgrs.iteritems():
            for tag in removed_tags:
                self._release_ipset(ip_version, tag)
            for tag in added_tags:
                _log.debug("Waiting for tag %s...", tag)
                self._acquire_ipset(ip_version, ipset_mgr, tag)
        self._maybe_update()

    def _maybe_update(self):
        if (len(self.pending_ipset_correlators[4]) == 0 and
                len(self.pending_ipset_correlators[6]) == 0):
            _log.debug("Ready to program rules for %s", self.id)
            self._update_chains()

    @actor_event
    def on_unreferenced(self):
        """
        Called to tell us that this profile is no longer needed.  Removes
        our iptables configuration.
        """
        for direction in ["inbound", "outbound"]:
            for ip_version, updater in self._iptables_updaters.iteritems():
                chain_name = profile_to_chain_name(direction, self.id)
                corr = next(_correlators)
                cb = functools.partial(self.on_chain_delete_complete,
                                       ip_version, direction, corr)
                self.pending_deletes[ip_version][direction] = corr
                updater.delete_chain("filter", chain_name, callback=cb,
                                     async=True)

        super(ProfileRules, self).on_unreferenced()

    @actor_event
    def on_chain_delete_complete(self, ip_version, direction, corr, error):
        if self.pending_deletes[ip_version].get(direction) == corr:
            self.pending_deletes[ip_version].pop(direction)
            if error:
                _log.error("Failed to delete rules for profile %s.  "
                           "Giving up.", error)
            if (len(self.pending_deletes[4]) == 0 and
                    len(self.pending_deletes[6]) == 0):
                self._programmed = False
                self._profile = None
                for ip_version in (4, 6):
                    for tag in (self._tag_to_ip_set_name[ip_version] +
                                self.pending_ipset_correlators[ip_version]):
                        self._release_ipset(ip_version, tag)
                self._notify_cleanup_complete()

    def _acquire_ipset(self, ip_version, ipset_mgr, tag):
        corr = next(_correlators)
        cb = functools.partial(self.on_ipset_ready, ip_version, corr)
        ipset_mgr.get_and_incref(tag, callback=cb, async=True)

    def _release_ipset(self, ip_version, tag):
        self._tag_to_ip_set_name[ip_version].pop(tag, None)
        self.pending_ipset_correlators[ip_version].pop(tag, None)
        self.ipset_mgrs[ip_version].decref(tag, async=True)

    @actor_event
    def on_ipset_ready(self, ip_version, corr, tag, ipset):
        current_corr = self.pending_ipset_correlators[ip_version].get(tag)
        if current_corr == corr:
            _log.debug("ipset ready for current correlator.")
            self.pending_ipset_correlators[ip_version].pop(tag)
            self._tag_to_ip_set_name[ip_version][tag] = ipset.name
        self._maybe_update()

    def _update_chains(self):
        """
        Updates the chains in the dataplane.
        """
        self._update_chain("inbound")
        self._update_chain("outbound")

    def _update_chain(self, direction):
        """
        Updates one of our individual inbound/outbound chains from
        the rules in the new_profile dict.

        :param direction: "inbound" or "outbound"
            must contain all tags used in the rules.
        """
        _log.debug("Updating %s chain", direction)
        new_profile = self._profile or {}
        rules_key = "%s_rules" % direction
        new_rules = new_profile.get(rules_key, [])

        _log.debug("Update to %s affects %s rules.", self.id, direction)
        for version, ipt in self._iptables_updaters.iteritems():
            chain_name = profile_to_chain_name(direction, self.id)
            updates = rules_to_chain_rewrite_lines(
                chain_name,
                new_rules,
                version,
                self._tag_to_ip_set_name[version],
                on_allow="RETURN")
            corr = next(_correlators)
            cb = functools.partial(self._on_iptables_update_complete,
                                   version, direction, corr)
            ipt.apply_updates("filter", [chain_name], updates, callback=cb,
                              async=True)

    def _on_iptables_update_complete(self, ip_version, direction, corr, error):
        if self.pending_updates[ip_version].get(direction) == corr:
            if error:
                _log.error("failed to program rules for profile %s", self.id)
            else:
                self.pending_updates[ip_version].pop(direction)
                self._maybe_notify_ready()

    def _maybe_notify_ready(self):
        if (not self._programmed and
                len(self.pending_updates[4]) == 0 and
                len(self.pending_updates[6]) == 0):
            self._notify_ready()
            self._programmed = True
            _log.info("Chains for %s programmed", self.id)


def extract_tags_from_profile(profile):
    if profile is None:
        return set()
    tags = set()
    for in_or_out in ["inbound_rules", "outbound_rules"]:
        for rule in profile.get(in_or_out, []):
            tags.update(extract_tags_from_rule(rule))
    return tags


def extract_tags_from_rule(rule):
    return set(rule[key] for key in ["src_tag", "dst_tag"]
               if key in rule and rule[key] is not None)
