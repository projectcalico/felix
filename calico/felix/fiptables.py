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
felix.fiptables
~~~~~~~~~~~~

IP tables management functions.
"""
from collections import defaultdict
import functools
import logging
from subprocess import CalledProcessError

from calico.felix.actor import Actor, actor_event, wait_and_check
from calico.felix.frules import (rules_to_chain_rewrite_lines,
                                 profile_to_chain_name, CHAIN_TO_PREFIX,
                                 CHAIN_FROM_PREFIX, CHAIN_TO_ENDPOINT,
                                 CHAIN_FROM_ENDPOINT)
from gevent import subprocess


_log = logging.getLogger(__name__)


class DispatchChains(Actor):
    """
    Actor that owns the felix-TO/FROM-ENDPOINT chains, which we use to 
    dispatch to endpoint-specific chains.

    LocalEndpoint Actors give us kicks as they come and go so we can
    add/remove them from the chains.
    """
    def __init__(self, iptables_updaters):
        super(DispatchChains, self).__init__()
        self.iptables_updaters = iptables_updaters
        self.iface_to_chain_suffix = {}

    @actor_event
    def on_endpoint_chains_ready(self, iface_name, chain_suffix):
        if self.iface_to_chain_suffix.get(iface_name) != chain_suffix:
            self.iface_to_chain_suffix[iface_name] = chain_suffix
            self._update_chains()

    @actor_event
    def remove_dispatch_rule(self, iface_name):
        if iface_name in self.iface_to_chain_suffix:
            self.iface_to_chain_suffix.pop(iface_name)
            self._update_chains()

    def _update_chains(self):
        updates = []
        for iface, chain in self.iface_to_chain_suffix.iteritems():
            # Add rule to global chain to direct traffic to the
            # endpoint-specific one.  Note that we use --goto, which means
            # that, the endpoint-specific chain will return to our parent
            # rather than to this chain.
            ep_from_chain = CHAIN_FROM_PREFIX + chain
            updates.append("--append %s --in-interface %s --goto %s" %
                           (CHAIN_FROM_ENDPOINT, iface, ep_from_chain))
            ep_to_chain = CHAIN_TO_PREFIX + chain
            updates.append("--append %s --out-interface %s --goto %s" %
                           (CHAIN_TO_ENDPOINT, iface, ep_to_chain))
        for ip_version, updater in self.iptables_updaters.iteritems():
            if ip_version == 6: continue # TODO IPv6
            updater.apply_updates("filter",
                                  [CHAIN_TO_ENDPOINT,
                                   CHAIN_FROM_ENDPOINT],
                                  updates)


class ActiveProfile(Actor):
    def __init__(self, profile_id, iptables_updaters):
        super(ActiveProfile, self).__init__()
        self.id = profile_id
        self._programmed = False
        self._iptables_updaters = iptables_updaters
        self._profile = None
        """:type dict: filled in by first update"""
        self._tag_to_ip_set_name = None
        """:type dict[str, str]: current mapping from tag name to ipset name."""

    @actor_event
    def ensure_chains_programmed(self):
        if self._programmed:
            return
        else:
            self._update_chains(self._profile, self._tag_to_ip_set_name)

    def _update_chains(self, profile, tag_to_ipset_name):
        futures = self._update_chain(profile, "inbound", tag_to_ipset_name)
        futures += self._update_chain(profile, "outbound", tag_to_ipset_name)
        wait_and_check(futures)
        self._programmed = True

    @actor_event
    def on_profile_update(self, profile, tag_to_ipset_name):
        """
        Update the programmed iptables configuration with the new
        profile
        """
        assert profile is None or profile["id"] == self.id

        self._update_chains(profile, tag_to_ipset_name)
        self._profile = profile
        self._tag_to_ip_set_name = tag_to_ipset_name

    @actor_event
    def remove(self):
        """
        Called to tell us that this profile is no longer needed.  Removes
        our iptables configuration.

        Thread safety: Caller should wait on the result of this method before
        creating a new ActiveProfile with the same name.  Otherwise, the
        delete calls in this method could be issued after the initialization
        of the new profile.
        """
        futures = []
        for direction in ["inbound", "outbound"]:
            chain_name = profile_to_chain_name(direction, self.id)
            for updater in self._iptables_updaters.values():
                f = updater.delete_chain(chain_name, async=True)
                futures.append(f)
        wait_and_check(futures)

        self._programmed = False
        self._profile = None
        self._tag_to_ip_set_name = None

    def _update_chain(self, new_profile, direction, tag_to_ipset_name):
        new_profile = new_profile or {}
        rules_key = "%s_rules" % direction
        new_rules = new_profile.get(rules_key, [])
        futures = []
        if (not self._programmed or
                self._profile is None or
                new_rules != self._profile.get(rules_key) or
                tag_to_ipset_name != self._tag_to_ip_set_name):
            _log.debug("Update to %s affects %s rules.", self.id, direction)
            chain_name = profile_to_chain_name(direction, self.id)
            for version, ipt in self._iptables_updaters.iteritems():
                if version == 6:
                    _log.error("Ignoring v6")
                    continue
                updates = rules_to_chain_rewrite_lines(chain_name,
                                                       new_rules,
                                                       version,
                                                       tag_to_ipset_name,
                                                       on_allow="RETURN")
                f = ipt.apply_updates("filter", [chain_name], updates,
                                      async=True)
                futures.append(f)
        else:
            _log.debug("Update to %s didn't affect %s rules.",
                       self.id, direction)
        return futures


class IptablesUpdater(Actor):
    """
    Actor that maintains an iptables-restore subprocess for
    injecting rules into iptables.

    Note: due to the internal architecture of IP tables,
    multiple concurrent calls to iptables-restore can clobber
    each other.  Use one instance of this class.
    """
    def __init__(self, ip_version=4):
        super(IptablesUpdater, self).__init__()
        if ip_version == 4:
            self.cmd_name = "iptables-restore"
        else:
            assert ip_version == 6
            self.cmd_name = "ip6tables-restore"

    @actor_event
    def apply_updates(self, table_name, required_chains, update_calls):
        """
        Atomically apply a set of updates to an iptables table.

        :param table_name: one of "raw" "mangle" "filter" "nat".
        :param required_chains: list of chains that the updates
               operate on; they will be created if needed.
        :param update_calls: list of iptables-style update calls,
               e.g. ["-A chain_name -j ACCEPT"] If rewriting a
               whole chain, start with "-F chain_name" to flush
               the chain.
        :returns an AsyncResult that may raise CalledProcessError
                 if a problem occurred.
        """
        # Run iptables-restore in noflush mode so that it doesn't
        # blow away all the tables we're not touching.

        # Valid input looks like this.
        #
        # *table
        # :chain_name
        # :chain_name_2
        # -F chain_name
        # -A chain_name -j ACCEPT
        # COMMIT
        #
        # The chains are created if they don't exist.
        chains = [":%s -" % c if isinstance(c, basestring) else ":%s %s" % c
                  for c in required_chains]
        restore_input = "\n".join(
            ["*%s" % table_name] +
            chains +
            update_calls +
            ["COMMIT\n"]
        )
        _log.debug("iptables-restore input:\n%s", restore_input)
        cmd = [self.cmd_name, "--noflush"]
        iptables_proc = subprocess.Popen(cmd,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        out, err = iptables_proc.communicate(restore_input)
        rc = iptables_proc.wait()
        if rc != 0:
            _log.error("Failed to run %s.\nOutput:%s\nError: %s",
                       self.cmd_name, out, err)
            raise CalledProcessError(cmd=cmd, returncode=rc)

    @actor_event
    def delete_chain(self, table_name, chain_name):
        updates = ["--delete-chain %s" % chain_name]
        self.apply_updates(table_name, [chain_name], updates)  # Skips queue.


class ActiveProfileManager(Actor):
    def __init__(self, iptables_updaters):
        super(ActiveProfileManager, self).__init__()
        self.profiles_by_id = {}
        self.profile_counts_by_id = defaultdict(lambda: 0)
        self.iptables_updaters = iptables_updaters

    @actor_event
    def get_profile_and_incref(self, profile_id):
        if profile_id not in self.profiles_by_id:
            ap = ActiveProfile(profile_id, self.iptables_updaters).start()
            self.profiles_by_id[profile_id] = ap
        self.profile_counts_by_id[profile_id] += 1
        return self.profiles_by_id[profile_id]

    @actor_event
    def return_profile(self, profile_id):
        self.profile_counts_by_id[profile_id] -= 1
        if self.profile_counts_by_id[profile_id] == 0:
            _log.debug("No more references to profile %s", profile_id)
            self._queue_profile_reap(profile_id)

    def _queue_profile_reap(self, dead_profile_id):
        ap = self.profiles_by_id[dead_profile_id]
        f = ap.remove(async=True)
        # We can't remove the profile until it's finished removing itself
        # so ask the result to call us back when it's done.  In the
        # meantime we might have revived the profile.
        f.rawlink(functools.partial(self._on_active_profile_removed,
                                    dead_profile_id, async=True))

    @actor_event
    def _on_active_profile_removed(self, profile_id):
        if self.profile_counts_by_id[profile_id] == 0:
            _log.debug("Reaping profile %s", profile_id)
            self.profiles_by_id.pop(profile_id)
            self.profile_counts_by_id.pop(profile_id)