# -*- coding: utf-8 -*-
# Copyright (c) Metaswitch Networks 2015. All rights reserved.
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
felix.felix
~~~~~~~~~~~

The main logic for Felix.
"""

# Monkey-patch before we do anything else...
from calico.felix.devices import InterfaceWatcher
from calico.felix.endpoint import EndpointManager
from calico.felix.fetcd import watch_etcd
from calico.felix.ipsets import IpsetManager
from gevent import monkey
monkey.patch_all()

import os

import logging
import gevent

from calico import common
from calico.felix.fiptables import (IptablesUpdater, DispatchChains,
                                    RulesManager)
from calico.felix.frules import install_global_rules
from calico.felix.dbcache import UpdateSequencer
from calico.felix.config import Config

_log = logging.getLogger(__name__)


def _main_greenlet(config):
    """
    The root of our tree of greenlets.  Responsible for restarting
    its children if desired.
    """
    try:
        _log.info("Creating actors.")
        v4_updater = IptablesUpdater(ip_version=4)
        v6_updater = IptablesUpdater(ip_version=6)
        iptables_updaters = {
            4: v4_updater,
            6: v6_updater,
        }
        v4_ipset_mgr = IpsetManager("hash:ip", family="inet")
        v6_ipset_mgr = IpsetManager("hash:ip", family="inet6")
        ipset_mgrs = {
            4: v4_ipset_mgr,
            6: v6_ipset_mgr,
        }
        profile_manager = RulesManager(iptables_updaters,
                                       ipset_mgrs)
        dispatch_chains = DispatchChains(config, iptables_updaters)
        endpoint_manager = EndpointManager(config, iptables_updaters,
                                           dispatch_chains, profile_manager)
        update_sequencer = UpdateSequencer(config, ipset_mgrs,
                                           v4_updater, v6_updater,
                                           dispatch_chains, profile_manager,
                                           endpoint_manager)
        iface_watcher = InterfaceWatcher(update_sequencer)

        _log.info("Starting actors.")
        profile_manager.start()
        dispatch_chains.start()
        v4_ipset_mgr.start()
        v6_ipset_mgr.start()
        endpoint_manager.start()
        update_sequencer.start()
        v4_updater.start()
        v6_updater.start()
        iface_watcher.start()
        greenlets = [profile_manager.greenlet,
                     dispatch_chains.greenlet,
                     update_sequencer.greenlet,
                     v4_ipset_mgr.greenlet,
                     v6_ipset_mgr.greenlet,
                     endpoint_manager.greenlet,
                     v4_updater.greenlet,
                     v6_updater.greenlet,
                     iface_watcher.greenlet]

        # Install the global rules before we start polling for updates.
        _log.info("Installing global rules.")
        install_global_rules(config, v4_updater, v6_updater)

        # Make sure we queue an initial update of the interfaces before the
        # etcd update.
        _log.info("Triggering initial interface poll..")
        iface_watcher.poll_interfaces(async=False)

        # Start polling for updates.
        _log.info("Starting polling for interface and etcd updates.")
        iface_watcher.watch_interfaces(async=True)  # Never returns, async!
        greenlets.append(gevent.spawn(watch_etcd, config, update_sequencer))

        # Wait for something to fail.
        # TODO: Maybe restart failed greenlets.
        stopped_greenlets_iter = gevent.iwait(greenlets)
        stopped_greenlet = next(stopped_greenlets_iter)
        try:
            stopped_greenlet.get()
        except Exception:
            _log.exception("Greenlet failed: %s", stopped_greenlet)
            raise
        else:
            _log.error("Greenlet %s unexpectedly returned.", stopped_greenlet)
            raise AssertionError("Greenlet unexpectedly returned")
    except:
        _log.exception("Exception killing main greenlet")
        raise


def watchdog():
    while True:
        _log.info("Still alive")
        gevent.sleep(20)


def main():
    try:
        # Initialise the logging with default parameters.
        common.default_logging()

        # Load config
        # FIXME: old felix used argparse but that's not in Python 2.6, so
        # hard-coded path.

        try:
            config = Config("/etc/calico/felix.cfg")
        except:
            # Attempt to open a log file, ignoring any errors it gets, before
            # we raise the exception.
            try:
                common.complete_logging("/var/log/calico/felix.log",
                                        logging.DEBUG,
                                        logging.DEBUG,
                                        logging.DEBUG)
            except:
                pass

            raise

        common.complete_logging(config.LOGFILE,
                                config.LOGLEVFILE,
                                config.LOGLEVSYS,
                                config.LOGLEVSCR)

        _log.info("Starting up")
        gevent.spawn(_main_greenlet, config).join()  # Should never return
    except BaseException:
        # Make absolutely sure that we exit by asking the OS to terminate our
        # process.  We don't want to let a stray background thread keep us
        # alive.
        _log.exception("Felix exiting due to exception")
        os._exit(1)
        raise  # Unreachable but keeps the linter happy about the broad except.
