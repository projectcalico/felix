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

import logging
from subprocess import CalledProcessError
import itertools
import time
import re
from types import StringTypes

from calico.felix.actor import Actor, actor_event, wait_and_check, \
    ReferenceManager
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

    queue_size = 100
    batch_delay = 0.1

    def __init__(self, config, iptables_updaters):
        super(DispatchChains, self).__init__()
        self.config = config
        self.iptables_updaters = iptables_updaters
        self.iface_to_ep_id = {}
        self.dirty = False

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
            self.dirty = True

    @actor_event
    def remove_dispatch_rule(self, iface_name):
        if iface_name in self.iface_to_ep_id:
            self.iface_to_ep_id.pop(iface_name, None)
            self.dirty = True

    def _on_batch_processed(self, batch, results):
        self._update_chains()
        self.dirty = False

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
            updater.apply_updates("filter",
                                  [CHAIN_TO_ENDPOINT,
                                   CHAIN_FROM_ENDPOINT],
                                  updates, async=False)


class ActiveProfile(Actor):
    """
    Actor that owns the per-profile rules chains.
    """
    def __init__(self, profile_id, iptables_updaters, ipset_mgrs):
        super(ActiveProfile, self).__init__()
        assert profile_id is not None
        self.id = profile_id
        self.ipset_mgrs = ipset_mgrs
        self._programmed = False
        self._iptables_updaters = iptables_updaters
        self._profile = None
        """:type dict: filled in by first update"""
        self._tag_to_ip_set_name = {4: {}, 6: {}}
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
            self._update_chains()

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
        for ip_version, ipset_mgr in self.ipset_mgrs.iteritems():
            for tag in removed_tags:
                self._tag_to_ip_set_name[ip_version].pop(tag, None)
                ipset_mgr.decref(tag)
            added_tags = new_tags - old_tags
            for tag in added_tags:
                ipset = ipset_mgr.get_and_incref(tag, async=False)
                self._tag_to_ip_set_name[ip_version][tag] = ipset.name

        self._profile = profile
        self._update_chains()

    @actor_event
    def on_unreferenced(self):
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
                                                       self.id)
                    f = updater.delete_chain("filter", chain_name, async=True)
                    futures.append(f)
            wait_and_check(futures)
            _log.debug("Finished deleting chains.")
        else:
            _log.debug("Chain wasn't yet programmed, nothing to do.")

        self._programmed = False
        self._profile = None
        for ip_version, ipset_mgr in self.ipset_mgrs.iteritems():
            for tag in self._tag_to_ip_set_name[ip_version]:
                ipset_mgr.decref(tag)
            self._tag_to_ip_set_name[ip_version] = {}

    def _update_chains(self):
        """
        Updates the chains in the dataplane.
        """
        futures = self._update_chain("inbound")
        futures += self._update_chain("outbound")
        wait_and_check(futures)
        self._programmed = True
        _log.info("Chains for %s programmed", self.id)

    def _update_chain(self, direction):
        """
        Updates one of our individual inbound/outbound chains from
        the rules in the new_profile dict.

        :param direction: "inbound" or "outbound"
            must contain all tags used in the rules.
        """
        new_profile = self._profile or {}
        rules_key = "%s_rules" % direction
        new_rules = new_profile.get(rules_key, [])
        futures = []

        _log.debug("Update to %s affects %s rules.", self.id, direction)
        for version, ipt in self._iptables_updaters.iteritems():
            chain_name = profile_to_chain_name(direction, self.id)
            updates = rules_to_chain_rewrite_lines(
                chain_name,
                new_rules,
                version,
                self._tag_to_ip_set_name[version],
                on_allow="RETURN")
            f = ipt.apply_updates("filter", [chain_name], updates,
                                  async=True)
            futures.append(f)

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

    queue_size = 1000
    batch_delay = 0.1

    def __init__(self, ip_version=4):
        super(IptablesUpdater, self).__init__()
        if ip_version == 4:
            self.cmd_name = "iptables-restore"
        else:
            assert ip_version == 6
            self.cmd_name = "ip6tables-restore"

        self.chains_to_flush = defaultdict(set)
        self.next_update_by_table_chain = defaultdict(dict)

    @actor_event
    def apply_updates(self, table_name, chains_to_flush, update_calls,
                      suppress_exc=False):
        """
        Atomically apply a set of updates to an iptables table.

        :param table_name: one of "raw" "mangle" "filter" "nat".
        :param chains_to_flush: list of chains that the updates
               operate on; they will be created if needed.
        :param update_calls: list of iptables-style update calls,
               e.g. ["-A chain_name -j ACCEPT"] If rewriting a
               whole chain, start with "-F chain_name" to flush
               the chain.
        :returns an AsyncResult that may raise CalledProcessError
                 if a problem occurred.
        """

        self.chains_to_flush[table_name].update(chains_to_flush)
        for chain in chains_to_flush:
            self.next_update_by_table_chain[table_name][chain] = []
        for call in update_calls:
            # FIXME: extracting chain name is ugly.
            chain_name = re.findall(r'^\s*\S+\s+(\S+)', call)[0]
            chains = self.next_update_by_table_chain[table_name]
            if not chains.get(chain_name):
                chains[chain_name] = []
            chains[chain_name].append(call)

    @actor_event
    def delete_chain(self, table_name, chain_name):
        _log.info("Deleting chain %s:%s", table_name, chain_name)
        self.next_update_by_table_chain[table_name][chain_name] = None
        self.chains_to_flush.add(chain_name)

    def _on_batch_processed(self, batch, results):

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

        start = time.time()
        updates = []
        for table, chains in self.next_update_by_table_chain.iteritems():
            updates.append("*%s" % table)
            for c in self.chains_to_flush[table]:
                updates.append(":%s -" % c if isinstance(c, StringTypes)
                                           else ":%s %s" % c)
            for chain_name, chain_updates in chains.iteritems():
                if chain_updates is None:
                    # Delete the chain
                    updates.append("--delete-chain %s" % chain_name)
                else:
                    updates.extend(chain_updates)
            updates.append("COMMIT\n")

        restore_input = "\n".join(updates)

        _log.debug("%s input:\n%s", self.cmd_name, restore_input)
        cmd = [self.cmd_name, "--noflush"]
        # TODO: retry if commit fails (due to concurrent use).
        iptables_proc = subprocess.Popen(cmd,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        out, err = iptables_proc.communicate(restore_input)
        rc = iptables_proc.wait()
        _log.debug("%s completed with RC=%s", self.cmd_name, rc)
        if rc != 0:
            _log.error("Failed to run %s.\nOutput:\n%s\n"
                       "Error:\n%s\nInput was:\n%s",
                       self.cmd_name, out, err, restore_input)
            # if not suppress_exc:
            #     raise CalledProcessError(cmd=cmd, returncode=rc)

        end = time.time()
        _log.debug("Batch time: %.2f %s", end - start, len(batch))
        self.chains_to_flush = defaultdict(set)
        self.next_update_by_table_chain = defaultdict(dict)



class ProfileManager(ReferenceManager):
    """
    Actor that manages the life cycle of ActiveProfile objects.
    Users must ensure that they correctly pair calls to
    get_and_incref() and decref().

    This class ensures that rules chains are properly quiesced
    before their Actors are deleted.
    """
    def __init__(self, iptables_updaters, ipset_mgrs):
        super(ProfileManager, self).__init__()
        self.iptables_updaters = iptables_updaters
        self.ipset_mgrs = ipset_mgrs
        self.profiles_by_id = {}

    def _create(self, profile_id):
        return ActiveProfile(profile_id, self.iptables_updaters,
                             self.ipset_mgrs)

    def _on_object_activated(self, profile_id, active_profile):
        profile_or_none = self.profiles_by_id.get(profile_id)
        active_profile.on_profile_update(profile_or_none, async=True)

    @actor_event
    def on_rules_update(self, profile_id, profile):
        if profile_id is not None:
            self.profiles_by_id[profile_id] = profile
        else:
            self.profiles_by_id.pop(profile_id, None)
        if self._is_active(profile_id):
            ap = self.objects_by_id[profile_id]
            ap.on_profile_update(profile, async=True)



def extract_tags_from_profile(profile):
    if profile is None:
        return set()
    tags = set()
    for in_or_out in ["inbound_rules", "outbound_rules"]:
        for rule in profile.get(in_or_out, []):
            tags.update(extract_tags_from_rule(rule))
    return tags


def extract_tags_from_rule(rule):
    return set([rule[key] for key in ["src_tag", "dst_tag"] if key in rule])
