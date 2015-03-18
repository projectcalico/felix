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


class RulesManager(ReferenceManager):
    """
    Actor that manages the life cycle of ProfileRules objects.
    Users must ensure that they correctly pair calls to
    get_and_incref() and decref().

    This class ensures that rules chains are properly quiesced
    before their Actors are deleted.
    """
    def __init__(self, ip_version, iptables_updater, ipset_manager):
        super(RulesManager, self).__init__()
        self.ip_version = ip_version
        self.iptables_updater = iptables_updater
        self.ipset_manager = ipset_manager
        self.rules_by_profile_id = {}

    def _create(self, profile_id):
        return ProfileRules(profile_id,
                            self.ip_version,
                            self.iptables_updater,
                            self.ipset_manager)

    def _on_object_started(self, profile_id, active_profile):
        profile_or_none = self.rules_by_profile_id.get(profile_id)
        _log.debug("Applying initial update to rules %s: %s", profile_id,
                   profile_or_none)
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
    def __init__(self, profile_id, ip_version, iptables_updater, ipset_mgr):
        super(ProfileRules, self).__init__()
        assert profile_id is not None

        self.id = profile_id
        self.ip_version = ip_version
        self.ipset_mgr = ipset_mgr
        self._iptables_updater = iptables_updater

        self.request_epoch = 1
        """Incremented each time we try to program the dataplane."""
        self.response_epoch = 0
        """Epoch of the last response we got from the dataplane."""

        self.pending_ipset_req_epochs = {}
        """
        Map from tag name to request epoch at which we requested that tag.
        Cleaned out when we get the response.
        """
        self.pending_ipset_decrefs = []
        """
        List of tuples of (req_epoch, tag name).  Added to when we want to
        discard a tag but have to wait for the ipchain to be updated before
        we can do so.  May contain the same tag multiple times if we've been
        adding and removing the tag a lot.  That's OK; we'll have increffed
        the tag the correct number of times as we requested it.
        """

        self._profile = None
        """
        :type dict|None: filled in by first update.  Reset to None on delete.
        """
        self._tag_to_ip_set_name = {}
        """
        :type dict[str, str]: current mapping from tag name to ipset name.
        """

    @actor_event
    def on_profile_update(self, profile):
        """
        Update the programmed iptables configuration with the new
        profile.
        """
        _log.debug("Profile update to %s: %s", self.id, profile)
        assert profile is None or profile["id"] == self.id

        old_tags = extract_tags_from_profile(self._profile)
        new_tags = extract_tags_from_profile(profile)

        removed_tags = old_tags - new_tags
        added_tags = new_tags - old_tags
        for tag in removed_tags:
            _log.debug("Queueing ipset for tag %s for decref", tag)
            self._queue_ipset_decref(tag)
        for tag in added_tags:
            _log.debug("Requesting ipset for tag %s", tag)
            self._request_ipset(tag)

        self._profile = profile
        self._maybe_update()

    def _maybe_update(self):
        if len(self.pending_ipset_req_epochs) == 0:
            _log.debug("Ready to program rules for %s", self.id)
            self._update_chains()
        else:
            _log.debug("Can't program rules %s yet, waiting on %s ipsets",
                       self.id, len(self.pending_ipset_req_epochs))

    @actor_event
    def on_unreferenced(self):
        """
        Called to tell us that this profile is no longer needed.  Removes
        our iptables configuration.
        """
        for tag in (self._tag_to_ip_set_name.keys() +
                    self.pending_ipset_req_epochs.keys()):
            self._queue_ipset_decref(tag)
        self._tag_to_ip_set_name = {}
        self.pending_ipset_req_epochs = {}
        self._profile = None

        chains = []
        for direction in ["inbound", "outbound"]:
            chain_name = profile_to_chain_name(direction, self.id)
            chains.append(chain_name)
        cb = functools.partial(self._on_chain_delete_complete,
                               self.request_epoch, async=True)
        self.request_epoch += 1
        self._iptables_updater.delete_chains("filter", chains,
                                             callback=cb, async=True)

    def _request_ipset(self, tag):
        cb = functools.partial(self.on_ipset_ready, self.request_epoch,
                               async=True)
        self.pending_ipset_req_epochs[tag] = self.request_epoch
        self.ipset_mgr.get_and_incref(tag, callback=cb, async=True)

    def _queue_ipset_decref(self, tag):
        self._tag_to_ip_set_name.pop(tag, None)
        self.pending_ipset_req_epochs.pop(tag, None)
        self.pending_ipset_decrefs.append((self.request_epoch, tag))

    @actor_event
    def on_ipset_ready(self, request_epoch, tag, ipset):
        if self.pending_ipset_req_epochs.get(tag) == request_epoch:
            _log.debug("ipset ready for current epoch.")
            self.pending_ipset_req_epochs.pop(tag)
            self._tag_to_ip_set_name[tag] = ipset.name
        else:
            _log.debug("Ignoring ipset update for old epoch. Out epoch: %s,"
                       "update: %s", self.pending_ipset_req_epochs.get(tag),
                       request_epoch)
        self._maybe_update()

    def _update_chains(self):
        """
        Updates the chains in the dataplane.
        """
        chains = []
        updates = []
        for direction in ("inbound", "outbound"):
            _log.debug("Updating %s chain for profile %s", direction,
                       self.id)
            new_profile = self._profile or {}
            _log.debug("Profile %s: %s", self.id, self._profile)
            rules_key = "%s_rules" % direction
            new_rules = new_profile.get(rules_key, [])
            chain_name = profile_to_chain_name(direction, self.id)
            chains.append(chain_name)
            updates.extend(rules_to_chain_rewrite_lines(
                chain_name,
                new_rules,
                self.ip_version,
                self._tag_to_ip_set_name,
                on_allow="RETURN"))
        _log.debug("Queueing programming for rules %s: %s", self.id,
                   updates)
        cb = functools.partial(self._on_iptables_update_complete,
                               self.request_epoch, async=True)
        self._iptables_updater.apply_updates("filter", chains, updates,
                                             callback=cb, async=True)
        self.request_epoch += 1

    @actor_event
    def _on_iptables_update_complete(self, request_epoch, error):
        assert request_epoch > self.response_epoch
        if not error:
            # Dataplane is now programmed up to at least this epoch...
            _log.info("Completed programming %s chains for epoch %s, "
                      "next req epoch: %s",
                      self.id, request_epoch, self.request_epoch)
            self.response_epoch = request_epoch
            self._clean_up_pending_decrefs()
            self._maybe_notify_ready()
        else:
            # FIXME: What to do when we fail?
            _log.error("Failed to program dataplane for epoch %s: %r",
                       request_epoch, error)

    @actor_event
    def _on_chain_delete_complete(self, request_epoch, error):
        assert request_epoch > self.response_epoch
        if not error:
            # Dataplane is now programmed up to at least this epoch...
            self.response_epoch = request_epoch
            self._profile = None
            self._clean_up_pending_decrefs()
        else:
            # FIXME: What to do when we fail?
            _log.error("Failed to delete chains, epoch %s: %r",
                       request_epoch, error)
        self._notify_cleanup_complete()

    def _maybe_notify_ready(self):
        if self.response_epoch > 0:
            self._notify_ready()
            _log.info("Chains for %s programmed", self.id)

    def _clean_up_pending_decrefs(self):
        decrefs = self.pending_ipset_decrefs
        while decrefs and decrefs[0][0] <= self.response_epoch:
            _, tag = decrefs.pop(0)
            self.ipset_mgr.decref(tag, async=True)


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
