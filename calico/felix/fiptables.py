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
import random
from subprocess import CalledProcessError
import time
import itertools

from calico.felix.actor import Actor, actor_event, ResultOrExc, SplitBatchAndRetry
from calico.felix.frules import (CHAIN_TO_ENDPOINT,
                                 CHAIN_FROM_ENDPOINT)
from gevent import subprocess
import gevent
import re
from types import StringTypes


_log = logging.getLogger(__name__)


class DispatchChains(Actor):
    """
    Actor that owns the felix-TO/FROM-ENDPOINT chains, which we use to
    dispatch to endpoint-specific chains.

    LocalEndpoint Actors give us kicks as they come and go so we can
    add/remove them from the chains.
    """

    queue_size = 1000
    batch_delay = 0.1

    def __init__(self, config, ip_version, iptables_updater):
        super(DispatchChains, self).__init__()
        self.request_epoch = 1
        self.response_epoch = 0

        self.config = config
        self.ip_version = ip_version
        self.iptables_updater = iptables_updater
        self.iface_to_ep_id = {}
        self._dirty = False
        self.removal_callback_queue = []

    @actor_event
    def on_endpoint_chains_ready(self, iface_name, endpoint_id):
        """
        Message sent to us by the LocalEndpoint to tell us its
        endpoint-specific chain is in place and we should add it
        to the dispatch chain.

        :param iface_name: name of the linux interface.
        :param endpoint_id: ID of the endpoint, used to form the chain names.
        """
        _log.debug("%s ready: %s/%s", self, iface_name, endpoint_id)
        if self.iface_to_ep_id.get(iface_name) != endpoint_id:
            self.iface_to_ep_id[iface_name] = endpoint_id
            self._dirty = True

    @actor_event
    def remove_dispatch_rule(self, iface_name, callback=None):
        _log.debug("%s asked to remove dispatch rule %s", self, iface_name)
        self.removal_callback_queue.append((self.request_epoch, callback))
        # It should be present but be defensive and reprogram the chain
        # just in case if not.
        self.iface_to_ep_id.pop(iface_name, None)
        self._dirty = True

    def _finish_msg_batch(self, batch, results):
        if self._dirty:
            self._update_chains()
            self._dirty = False

    def _update_chains(self):
        _log.info("%s Updating dispatch chain, num entries: %s", self,
                  len(self.iface_to_ep_id))
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
        cb = functools.partial(self.on_ipt_update_complete, self.request_epoch,
                               async=True)
        self.request_epoch += 1
        self.iptables_updater.apply_updates("filter",
                                            [CHAIN_TO_ENDPOINT,
                                             CHAIN_FROM_ENDPOINT],
                                            updates, callback=cb, async=True)

    @actor_event
    def on_ipt_update_complete(self, request_epoch, error):
        assert request_epoch > self.response_epoch
        if not error:
            # Dataplane is now programmed up to at least this epoch...
            _log.info("%s update %s complete", self, request_epoch)
            self.response_epoch = request_epoch
            self._fire_pending_callbacks()
        else:
            # FIXME: What to do when we fail?
            _log.error("%s failed to program dataplane for epoch %s: %r",
                       self, request_epoch, error)

    def _fire_pending_callbacks(self):
        pending_cbs = self.removal_callback_queue
        while pending_cbs and pending_cbs[0][0] <= self.response_epoch:
            _, cb = pending_cbs.pop(0)
            cb(None)

    def __str__(self):
        return self.__class__.__name__ + "<ipv%s,entries=%s>" % \
            (self.ip_version, len(self.iface_to_ep_id))

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
        self.completion_callbacks = []

    @actor_event
    def apply_updates(self, table_name, chains_to_flush, update_calls,
                      callback=None, suppress_exc=False):
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
        _log.debug("Iptables update: %s\n%s", chains_to_flush, update_calls)
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
        self.completion_callbacks.append(callback)

    @actor_event
    def delete_chains(self, table_name, chain_names, callback=None):
        # We actually apply the changes in _finish_msg_batch().  Index the
        # changes by table and chain.
        _log.info("Deleting chains %s:%s", table_name, chain_names)
        # Put an explicit None in the index to mark it for deletion.
        self.chains_to_flush[table_name].update(chain_names)
        for chain_name in chain_names:
            self.batched_updates_by_table_chain[table_name][chain_name] = None
        self.completion_callbacks.append(callback)

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
                _log.error("Non-retryable %s failure. RC=%s", self.cmd_name,
                           e.returncode)
                cb = self.completion_callbacks[0]
                if batch[0].partial.keywords.get("suppress_exc"):
                    final_result = ResultOrExc(None, None)
                else:
                    final_result = ResultOrExc(None, e)
                if cb:
                    if batch[0].partial.keywords.get("suppress_exc"):
                        cb(None)
                    else:
                        cb(e)
                results[0] = final_result
            else:
                _log.error("Non-retryable error from a combined batch, "
                           "splitting the batch to narrow down culprit.")
                raise SplitBatchAndRetry()
        else:
            for c in self.completion_callbacks:
                if c:
                    c(None)
        finally:
            self._reset_batched_work()

        end = time.time()
        _log.debug("Batch time: %.2f %s", end - start, len(batch))

    def _reset_batched_work(self):
        self.chains_to_flush = defaultdict(set)
        self.batched_updates_by_table_chain = defaultdict(dict)
        self.completion_callbacks = []

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
