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
import random
import gevent
import re
from types import StringTypes

from calico.felix.actor import Actor, actor_event, wait_and_check, \
    ReferenceManager, ResultOrExc, SplitBatchAndRetry
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

    def _finish_msg_batch(self, batch, results):
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
            # TODO Handle failure to program chain
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
            # TODO Handle failure to program chain
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
                _log.debug("Waiting for tag %s...", tag)
                ipset = ipset_mgr.get_and_incref(tag, async=False)
                _log.debug("got tag %s", tag)
                self._tag_to_ip_set_name[ip_version][tag] = ipset.name

        self._profile = profile
        # TODO Handle failure to program chain
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
        _log.debug("Updating %s chain", direction)
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
MAX_IPT_RETRIES = 10
MAX_IPT_BACKOFF = 0.2


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
        self.batched_updates_by_table_chain = defaultdict(dict)

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
        :returns CalledProcessError if a problem occurred.
        """
        # We actually apply the changes in _finish_msg_batch().  Index the
        # changes by table and chain.
        self.chains_to_flush[table_name].update(chains_to_flush)
        for chain in chains_to_flush:
            # Even if a previous update in this batch added some updates to
            # this chain, this new update flushes the chain so we discard the
            # updates.
            self.batched_updates_by_table_chain[table_name][chain] = []
        for call in update_calls:
            # FIXME: extracting chain name is ugly.
            chain_name = re.findall(r'^\s*\S+\s+(\S+)', call)[0]
            chains = self.batched_updates_by_table_chain[table_name]
            if chains.get(chain_name) is None:
                # Note: chain may be explicitly set to None to indicate
                # deletion.  This will resurrect it if so.
                chains[chain_name] = []
            chains[chain_name].append(call)

    @actor_event
    def delete_chain(self, table_name, chain_name):
        # We actually apply the changes in _finish_msg_batch().  Index the
        # changes by table and chain.
        _log.info("Deleting chain %s:%s", table_name, chain_name)
        # Put an explicit None in the index to mark it for deletion.
        self.chains_to_flush.add(chain_name)
        self.batched_updates_by_table_chain[table_name][chain_name] = None

    def _execute_current_batch(self):

        updates_by_table_chain = self.batched_updates_by_table_chain
        input_lines = self._calculate_ipt_input(updates_by_table_chain)
        self._execute_iptables(input_lines)

    def _start_msg_batch(self, batch):
        self._reset_batched_work()
        return batch

    def _finish_msg_batch(self, batch, results):
        start = time.time()

        try:
            self._execute_current_batch()
        except CalledProcessError as e:
            if len(batch) == 1:
                _log.error("Unrecoverable %s failure. RC=%s", self.cmd_name,
                           e.returncode)
                if batch[0].partial.keywords.get("suppress_exc"):
                    final_result = ResultOrExc(None, None)
                else:
                    final_result = ResultOrExc(None, e)
                results[0] = final_result
            else:
                _log.error("Unrecoverable error from a combined batch, "
                           "splitting the batch to narrow down culprit.")
                raise SplitBatchAndRetry()
        finally:
            self._reset_batched_work()

        end = time.time()
        _log.debug("Batch time: %.2f %s", end - start, len(batch))

    def _reset_batched_work(self):
        self.chains_to_flush = defaultdict(set)
        self.batched_updates_by_table_chain = defaultdict(dict)

    def _calculate_ipt_input(self, updates_by_table_chain):
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
        input_lines = []
        for table, chains in updates_by_table_chain.iteritems():
            input_lines.append("*%s" % table)
            for c in self.chains_to_flush[table]:
                input_lines.append(":%s -" % c if isinstance(c, StringTypes)
                               else ":%s %s" % c)
            for chain_name, chain_updates in chains.iteritems():
                if chain_updates is None:
                    # Delete the chain
                    input_lines.append("--delete-chain %s" % chain_name)
                else:
                    input_lines.extend(chain_updates)
            input_lines.append("COMMIT\n")
        return input_lines

    def _execute_iptables(self, input_lines):
        """
        Runs ip(6)tables-restore with the given input.  Retries iff
        the COMMIT fails.

        :raises CalledProcessError: if the command fails on a non-commit
            line or if it repeatedly fails and retries are exhausted.
        """
        backoff = 0.01
        num_tries = 0
        success = False
        while not success:
            input_str = "\n".join(input_lines)
            _log.debug("%s input:\n%s", self.cmd_name, input_str)

            # Run iptables-restore in noflush mode so that it doesn't
            # blow away all the tables we're not touching.
            cmd = [self.cmd_name, "--noflush"]
            iptables_proc = subprocess.Popen(cmd,
                                             stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)
            out, err = iptables_proc.communicate(input_str)
            rc = iptables_proc.wait()
            _log.debug("%s completed with RC=%s", self.cmd_name, rc)
            num_tries += 1
            if rc == 0:
                success = True
            else:
                # Parse the output to determine if error is retryable.
                _log.error("Failed to run %s.\nOutput:\n%s\n"
                           "Error:\n%s\nInput was:\n%s",
                           self.cmd_name, out, err, input_str)
                match = re.search(r"line (\d+) failed", err)
                if match:
                    # Have a line number, work out if this was a commit
                    # failure, which is caused by concurrent access and is
                    # retryable.
                    line_number = int(match.group(1))
                    _log.debug("%s failure on line %s", self.cmd_name,
                               line_number)
                    line_index = line_number - 1
                    offending_line = input_lines[line_index]
                    if (num_tries < MAX_IPT_RETRIES and
                            offending_line.strip() == "COMMIT"):
                        _log.info("Failure occurred on COMMIT line, error is "
                                  "retryable. Retry in %.2fs", backoff)
                        gevent.sleep(backoff)
                        if backoff > MAX_IPT_BACKOFF:
                            backoff = MAX_IPT_BACKOFF
                        backoff *= (1.5 + random.random())
                    elif num_tries >= MAX_IPT_RETRIES:
                        _log.error("Out of retries.  Error occurred on line "
                                   "%s: %r", line_number, offending_line)
                    else:
                        _log.error("Unrecoverable error on line %s: %r",
                                   line_number, offending_line)
                raise CalledProcessError(cmd=cmd, returncode=rc)


class RulesManager(ReferenceManager):
    """
    Actor that manages the life cycle of ActiveProfile objects.
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
        return ActiveProfile(profile_id, self.iptables_updaters,
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
