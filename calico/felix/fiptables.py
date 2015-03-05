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
import logging
from subprocess import CalledProcessError
from calico.felix.actor import Actor, actor_event, wait_and_check
from calico.felix.frules import (CHAIN_PROFILE_PREFIX,
                                 rules_to_chain_rewrite_lines,
                                 profile_to_chain_name)
from gevent import subprocess

_log = logging.getLogger(__name__)


class ActiveProfile(Actor):
    def __init__(self, profile_id, iptables_updaters):
        super(ActiveProfile, self).__init__()
        self.id = profile_id
        self._iptables_updaters = iptables_updaters
        self._profile = None
        """:type dict: filled in by first update"""
        self._tag_to_ip_set_name = None
        """:type dict[str, str]: current mapping from tag name to ipset name."""

    @actor_event
    def on_profile_update(self, profile, tag_to_ipset_name):
        """
        Update the programmed iptables configuration with the new
        profile
        """
        assert profile["id"] == self.id

        futures = self._update_chain(profile, "inbound", tag_to_ipset_name)
        futures += self._update_chain(profile, "outbound", tag_to_ipset_name)
        wait_and_check(futures)

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

        self._profile = None
        self._tag_to_ip_set_name = None

    def _update_chain(self, new_profile, direction, tag_to_ipset_name):
        new_rules = new_profile.get(direction, [])
        if (self._profile is None or
            new_rules != self._profile.get(direction) or
            tag_to_ipset_name != self._tag_to_ip_set_name):
            _log.debug("Update to %s affects %s rules.", self.id, direction)
            chain_name = profile_to_chain_name(direction, self.id)
            futures = []
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
            return futures
        else:
            _log.debug("Update to %s didn't affect %s rules.",
                       self.id, direction)


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