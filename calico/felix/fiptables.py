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
from calico.felix.actor import Actor, actor_event
from gevent import subprocess

_log = logging.getLogger(__name__)


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

