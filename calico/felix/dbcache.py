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
import logging
import socket

from calico.felix.actor import actor_event, Actor

_log = logging.getLogger(__name__)


OUR_HOSTNAME = socket.gethostname()


class UpdateSequencer(Actor):
    def __init__(self, config, tag_mgr, v4_updater, v6_updater,
                 dispatch_chains, profile_manager, endpoint_manager):
        super(UpdateSequencer, self).__init__()

        # Peers/utility classes.
        self.config = config
        self.tag_mgr = tag_mgr
        self.endpoint_mgr = endpoint_manager
        self.v4_updater = v4_updater
        self.v6_updater = v6_updater
        self.iptables_updaters = {
            4: v4_updater,
            6: v6_updater,
        }
        self.dispatch_chains = dispatch_chains
        self.profile_mgr = profile_manager

    @actor_event
    def apply_snapshot(self, rules_by_prof_id, tags_by_prof_id,
                       endpoints_by_id):
        """
        Replaces the whole cache state with the input.  Applies deltas vs the
        current active state.
        """

        # Step 1: fire in data update events to the profile and tag managers
        # so they can build their indexes before we activate anything.
        _log.info("Applying snapshot. STAGE 1a: rules.")
        for profile_id, rules in rules_by_prof_id.iteritems():
            self.profile_mgr.on_rules_update(profile_id, rules, async=True)
        _log.info("Applying snapshot. STAGE 1b: tags.")
        for profile_id, tags in tags_by_prof_id.iteritems():
            self.tag_mgr.on_tags_update(profile_id, tags, async=True)
        _log.info("Applying snapshot. STAGE 1c: endpoints->tag mgr.")
        for endpoint_id, endpoint in endpoints_by_id.iteritems():
            self.tag_mgr.on_endpoint_update(endpoint_id, endpoint, async=True)

        # Step 2: fire in update events into the endpoint manager, which will
        # recursively trigger activation of profiles and tags.
        _log.info("Applying snapshot. STAGE 2: endpoints->endpoint mgr.")
        for endpoint_id, endpoint in endpoints_by_id.iteritems():
            self.endpoint_mgr.on_endpoint_update(endpoint_id, endpoint,
                                                 async=True)
        # TODO: clean up unused chains.
        _log.info("Applying snapshot. DONE. %s rules, %s tags, "
                  "%s endpoints", len(rules_by_prof_id), len(tags_by_prof_id),
                  len(endpoints_by_id))

    @actor_event
    def on_rules_update(self, profile_id, rules):
        """
        Process an update to the rules of the given profile.
        :param dict[str,list[dict]] rules: New set of inbound/outbound rules
            or None if the rules have been deleted.
        """
        _log.info("Profile update: %s", profile_id)
        self.profile_mgr.on_rules_update(profile_id, rules, async=True)

    @actor_event
    def on_tags_update(self, profile_id, tags):
        """
        Called when the given tag list has changed or been deleted.
        :param list[str] tags: List of tags for the given profile or None if
            deleted.
        """
        _log.info("Tags for profile %s updated", profile_id)
        self.tag_mgr.on_tags_update(profile_id, tags, async=True)

    @actor_event
    def on_interface_update(self, name, iface_state):
        _log.info("Interface %s changed state: %s", name, iface_state)
        self.endpoint_mgr.on_interface_update(name, iface_state, async=True)

    @actor_event
    def on_endpoint_update(self, endpoint_id, endpoint):
        """
        Process an update to the given endpoint.  endpoint may be None if
        the endpoint was deleted.
        """
        _log.info("Endpoint update for %s.", endpoint_id)
        self.tag_mgr.on_endpoint_update(endpoint_id, endpoint, async=True)
        self.endpoint_mgr.on_endpoint_update(endpoint_id, endpoint, async=True)
