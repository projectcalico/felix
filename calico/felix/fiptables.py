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
import itertools
from types import StringTypes

from calico.felix.actor import Actor, actor_event, wait_and_check
from calico.felix.frules import (rules_to_chain_rewrite_lines,
                                 profile_to_chain_name, CHAIN_TO_ENDPOINT,
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
    def __init__(self, config, iptables_updaters):
        super(DispatchChains, self).__init__()
        self.config = config
        self.iptables_updaters = iptables_updaters
        self.iface_to_ep_id = {}

    @actor_event
    def on_endpoint_chains_ready(self, iface_name, endpoint_id):
        """
        Message sent to us by the LocalEndpoint to tell us its
        endpoint-specific chain is in place and we should add it
        to the dispatch chain.

        :param iface_name: name of the linux interface.
        :param endpoint_id: ID of the endpoint, used to form the chain names.
        """
        if self.iface_to_ep_id.get(iface_name) != endpoint_id:
            self.iface_to_ep_id[iface_name] = endpoint_id
            self._update_chains()

    @actor_event
    def remove_dispatch_rule(self, iface_name):
        if iface_name in self.iface_to_ep_id:
            self.iface_to_ep_id.pop(iface_name)
            self._update_chains()

    def _update_chains(self):
        updates = []
        for iface in self.iface_to_ep_id:
            # Add rule to global chain to direct traffic to the
            # endpoint-specific one.  Note that we use --goto, which means
            # that, the endpoint-specific chain will return to our parent
            # rather than to this chain.
            from calico.felix.endpoint import chain_names, interface_to_suffix
            ep_suffix = interface_to_suffix(self.config, iface)
            to_chain_name, from_chain_name = chain_names(ep_suffix)
            updates.append("--append %s --in-interface %s --goto %s" %
                           (CHAIN_FROM_ENDPOINT, iface, from_chain_name))
            updates.append("--append %s --out-interface %s --goto %s" %
                           (CHAIN_TO_ENDPOINT, iface, to_chain_name))
        updates.extend(["--append %s --jump DROP" % CHAIN_TO_ENDPOINT,
                        "--append %s --jump DROP" % CHAIN_FROM_ENDPOINT])
        for ip_version, updater in self.iptables_updaters.iteritems():
            if ip_version == 6: continue # TODO IPv6
            updater.apply_updates("filter",
                                  [CHAIN_TO_ENDPOINT,
                                   CHAIN_FROM_ENDPOINT],
                                  updates)


class ActiveProfile(Actor):
    """
    Actor that owns the per-profile rules chains.
    """
    def __init__(self, profile_id, iptables_updaters):
        super(ActiveProfile, self).__init__()
        assert profile_id is not None
        self.id = profile_id
        self._programmed = False
        self._iptables_updaters = iptables_updaters
        self._profile = None
        """:type dict: filled in by first update"""
        self._tag_to_ip_set_name = None
        """:type dict[str, str]: current mapping from tag name to ipset name."""

    @actor_event
    def ensure_chains_programmed(self):
        """
        Waits until the chains are actually programmed into the dataplane.

        Used by the endpoint actor to make sure that it doesn't program its
        chains, which reference the profile chain, until the profile chain
        is present.
        """
        if self._programmed:
            return
        else:
            self._update_chains(self._profile, self._tag_to_ip_set_name)

    def _update_chains(self, profile, tag_to_ipset_name):
        """
        Updates the chains in the dataplane.
        :param profile: The profile dict, containing hte inbound and
            outbound rules.
        :param tag_to_ipset_name: Dict that maps from name of tag to name of
            ipset to use i the rules.
        """
        futures = self._update_chain(profile, "inbound", tag_to_ipset_name)
        futures += self._update_chain(profile, "outbound", tag_to_ipset_name)
        wait_and_check(futures)
        self._programmed = True
        _log.info("Chains for %s programmed", self.id)

    @actor_event
    def on_profile_update(self, profile, tag_to_ipset_name):
        """
        Update the programmed iptables configuration with the new
        profile.  Returns after the update is present in the dataplane.
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
        if self._programmed:
            _log.debug("Chain was programmed, removing it.")
            for direction in ["inbound", "outbound"]:
                for ip_version, updater in self._iptables_updaters.iteritems():
                    chain_name = profile_to_chain_name(direction,
                                                       self.id,
                                                       ip_version)
                    f = updater.delete_chain("filter", chain_name, async=True)
                    futures.append(f)
            wait_and_check(futures)
            _log.debug("Finished deleting chains.")
        else:
            _log.debug("Chain wasn't yet programmed, nothing to do.")

        self._programmed = False
        self._profile = None
        self._tag_to_ip_set_name = None

    def _update_chain(self, new_profile, direction, tag_to_ipset_name):
        """
        Updates one of our individual inbound/outbound chains from
        the rules in the new_profile dict.

        :param direction: "inbound" or "outbound"
        :param tag_to_ipset_name: dict mapping name of tag to ipset name,
            must contain all tags used in the rules.
        """
        new_profile = new_profile or {}
        rules_key = "%s_rules" % direction
        new_rules = new_profile.get(rules_key, [])
        futures = []
        if (not self._programmed or
                self._profile is None or
                new_rules != self._profile.get(rules_key) or
                tag_to_ipset_name != self._tag_to_ip_set_name):
            _log.debug("Update to %s affects %s rules.", self.id, direction)
            for version, ipt in self._iptables_updaters.iteritems():
                chain_name = profile_to_chain_name(direction, self.id)
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


_correlators = ("ipt-%s" % ii for ii in itertools.count())


class IptablesUpdater(Actor):
    """
    Actor that maintains an iptables-restore subprocess for
    injecting rules into iptables.

    Note: due to the internal architecture of iptables,
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
    def apply_updates(self, table_name, required_chains, update_calls,
                      suppress_exc=False):
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
        corr = next(_correlators)
        chains = [":%s -" % c if isinstance(c, StringTypes) else ":%s %s" % c
                  for c in required_chains]
        restore_input = "\n".join(
            ["*%s" % table_name] +
            chains +
            update_calls +
            ["COMMIT\n"]
        )
        _log.debug("%s %s input:\n%s", corr, self.cmd_name, restore_input)
        cmd = [self.cmd_name, "--noflush"]
        # TODO: retry if commit fails (due to concurrent use).
        iptables_proc = subprocess.Popen(cmd,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        out, err = iptables_proc.communicate(restore_input)
        rc = iptables_proc.wait()
        _log.debug("%s %s completed with RC=%s", corr, self.cmd_name, rc)
        if rc != 0:
            _log.error("%s Failed to run %s.\nOutput:%s\nError: %s",
                       corr, self.cmd_name, out, err)
            if not suppress_exc:
                raise CalledProcessError(cmd=cmd, returncode=rc)

    @actor_event
    def delete_chain(self, table_name, chain_name):
        _log.info("Deleting chain %s:%s", table_name, chain_name)
        updates = ["--delete-chain %s" % chain_name]
        self.apply_updates(table_name, [chain_name], updates)  # Skips queue.
        _log.debug("Finished deleting chain.")


class ActiveProfileManager(Actor):
    """
    Actor that manages the life cycle of ActiveProfile objects.
    Users must ensure that they correctly pair calls to
    get_profile_and_incref() and return_profile().

    This class ensures that rules chains are properly quiesced
    before thier Actors are deleted.
    """
    def __init__(self, iptables_updaters):
        super(ActiveProfileManager, self).__init__()
        self.profiles_by_id = {}
        self.profile_counts_by_id = defaultdict(lambda: 0)
        self.iptables_updaters = iptables_updaters

    @actor_event
    def get_profile_and_incref(self, profile_id):
        assert profile_id is not None
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
        """
        Asks the profile to remove itself from the dataplane and
        queues a callback to tell us that that work is complete.
        """
        ap = self.profiles_by_id[dead_profile_id]
        f = ap.remove(async=True)

        # We can't delete the profile Actor until it's finished removing
        # itself so ask the result to call us back when it's done.  In the
        # meantime we might have revived the profile.

        def callback(greenlet):
            self._on_active_profile_removed(dead_profile_id, async=True)
        f.rawlink(callback)

    @actor_event
    def _on_active_profile_removed(self, profile_id):
        """
        Callback we queue when deleting an ActiveProfile Actor.
        checks that the Actor is still unreferenced before cleaning
        it up.
        """
        if self.profile_counts_by_id[profile_id] == 0:
            # Profile is still dead, clean it up.  Note: if the profile
            # was revived and then removed again, we might get multiple
            # calls to this method so we're defensive and use pop() to
            # delete the profile/counter (in case we already did so).
            _log.debug("Reaping profile %s", profile_id)
            self.profiles_by_id.pop(profile_id)
            self.profile_counts_by_id.pop(profile_id)
