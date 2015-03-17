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

from calico.felix.actor import Actor, actor_event, ResultOrExc, SplitBatchAndRetry
from calico.felix.frules import (CHAIN_TO_ENDPOINT,
                                 CHAIN_FROM_ENDPOINT)


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
