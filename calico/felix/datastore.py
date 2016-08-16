# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
felix.datastore
~~~~~~~~~~~~

Our API to etcd.  Contains function to synchronize felix with etcd
as well as reporting our status into etcd.
"""
import os
import random
import logging
import signal
import socket
import subprocess

import gevent
import sys
from gevent.event import Event

from calico import common
from calico.datamodel_v1 import (
    VERSION_DIR, CONFIG_DIR, dir_for_per_host_config, PROFILE_DIR, HOST_DIR,
    WloadEndpointId, ENDPOINT_STATUS_ERROR,
    ENDPOINT_STATUS_DOWN, ENDPOINT_STATUS_UP,
    POLICY_DIR, TieredPolicyId, HostEndpointId, EndpointId)
from calico.etcddriver.protocol import *
from calico.felix.actor import Actor, actor_message, TimedGreenlet
from calico.felix.futils import (
    logging_exceptions, iso_utc_timestamp, IPV4,
    IPV6, StatCounter
)
from calico.monotonic import monotonic_time

_log = logging.getLogger(__name__)


RETRY_DELAY = 5

# Etcd paths that we care about for use with the PathDispatcher class.
# We use angle-brackets to name parameters that we want to capture.
PER_PROFILE_DIR = PROFILE_DIR + "/<profile_id>"
TAGS_KEY = PER_PROFILE_DIR + "/tags"
RULES_KEY = PER_PROFILE_DIR + "/rules"
PROFILE_LABELS_KEY = PER_PROFILE_DIR + "/labels"
PER_HOST_DIR = HOST_DIR + "/<hostname>"
HOST_IP_KEY = PER_HOST_DIR + "/bird_ip"
WORKLOAD_DIR = PER_HOST_DIR + "/workload"
HOST_IFACE_DIR = PER_HOST_DIR + "/endpoint"
HOST_IFACE_KEY = PER_HOST_DIR + "/endpoint/<endpoint_id>"
PER_ORCH_DIR = WORKLOAD_DIR + "/<orchestrator>"
PER_WORKLOAD_DIR = PER_ORCH_DIR + "/<workload_id>"
ENDPOINT_DIR = PER_WORKLOAD_DIR + "/endpoint"
PER_ENDPOINT_KEY = ENDPOINT_DIR + "/<endpoint_id>"
CONFIG_PARAM_KEY = CONFIG_DIR + "/<config_param>"
PER_HOST_CONFIG_PARAM_KEY = PER_HOST_DIR + "/config/<config_param>"
TIER_DATA = POLICY_DIR + "/tier/<tier>/metadata"
TIERED_PROFILE = POLICY_DIR + "/tier/<tier>/policy/<policy_id>"

IPAM_DIR = VERSION_DIR + "/ipam"
IPAM_V4_DIR = IPAM_DIR + "/v4"
POOL_V4_DIR = IPAM_V4_DIR + "/pool"
CIDR_V4_KEY = POOL_V4_DIR + "/<pool_id>"

# Max number of events from driver process before we yield to another greenlet.
MAX_EVENTS_BEFORE_YIELD = 200


# Global diagnostic counters.
_stats = StatCounter("Etcd counters")


class DatastoreAPI(Actor):
    """
    Our API to the datastore via the backend driver process.
    """

    def __init__(self, config, hosts_ipset):
        super(DatastoreAPI, self).__init__(config.ETCD_ADDRS)
        self._config = config
        self.hosts_ipset = hosts_ipset

        # Timestamp storing when the DatastoreAPI started. This info is needed
        # in order to report uptime to etcd.
        self._start_time = monotonic_time()

        # the Popen object for the driver subprocess.
        self._driver_process = None

        # The main etcd-watching greenlet.
        self._reader = None

        # One-way flag indicating we're being shut down.
        self.killed = False

    def _on_actor_started(self):
        _log.info("%s starting worker threads", self)
        reader, writer = self._start_driver_process()

        self.write_api = DatastoreWriter(self._config, writer)
        self.write_api.start()  # Sends the init message to the back-end.

        self._reader = DatastoreReader(
            self._config,
            reader,
            self.write_api,
            self.hosts_ipset,
            self._driver_process,
        )
        self._reader.link(self._on_worker_died)
        self._reader.start()

    def _start_driver_process(self):
        """
        Starts the driver subprocess, connects to it over the socket
        and sends it the init message.

        Stores the Popen object in self._driver_process for future
        access.

        :return: the connected socket to the driver.
        """
        _log.info("Creating server socket.")
        if os.path.exists("/run"):
            # Linux FHS version 3.0+ location for runtime sockets etc.
            sck_filename = "/run/felix-driver.sck"
        else:
            # Older Linux versions use /var/run.
            sck_filename = "/var/run/felix-driver.sck"
        try:
            os.unlink(sck_filename)
        except OSError:
            _log.debug("Failed to delete driver socket, assuming it "
                       "didn't exist.")
        update_socket = socket.socket(socket.AF_UNIX,
                                      socket.SOCK_STREAM)
        update_socket.bind(sck_filename)
        update_conn = None
        try:
            update_socket.listen(1)
            cmd = self.driver_cmd(sck_filename)
            _log.info("etcd-driver command line: %s", cmd)
            if self.killed:
                _log.critical("Not starting driver: process is shutting down.")
                raise Exception("Driver shut down.")
            self._driver_process = subprocess.Popen(cmd)
            _log.info("Started etcd driver with PID %s",
                      self._driver_process.pid)
            with gevent.Timeout(10):
                update_conn, _ = update_socket.accept()
            _log.info("Accepted connection on socket")
        except gevent.Timeout:
            _log.exception("Backend failed to connect within timeout, "
                           "giving up.")
            raise
        finally:
            # No longer need the server socket, remove it.
            try:
                os.unlink(sck_filename)
            except OSError:
                # Unexpected but carry on...
                _log.exception("Failed to unlink socket. Ignoring.")
            else:
                _log.info("Unlinked server socket")

        # Wrap the socket in reader/writer objects that simplify using the
        # protocol.
        reader = MessageReader(update_conn)
        writer = MessageWriter(update_conn)
        return reader, writer

    def driver_cmd(self, sck_filename):
        if getattr(sys, "frozen", False):
            # We're running under pyinstaller, where we share our
            # executable with the etcd driver.  Re-run this executable
            # with the "driver" argument to invoke the etcd driver.
            cmd = [sys.argv[0], "driver"]
        else:
            # Not running under pyinstaller, execute the etcd driver
            # directly.
            cmd = [sys.executable, "-m", "calico.etcddriver"]
        # etcd driver takes the felix socket name as argument.
        cmd = ["/home/gulfstream/go-work/src/github.com/tigera/"
               "libcalico-go/bin/felix-backend"]
        cmd += [sck_filename]
        return cmd

    @actor_message()
    def load_config(self):
        """
        Loads our config from etcd, should only be called once.

        :return: an Event which is triggered when the config has been loaded.
        """
        self._reader.load_config.set()
        return self._reader.configured

    @actor_message()
    def start_watch(self, splitter):
        """
        Starts watching etcd for changes.  Implicitly loads the config
        if it hasn't been loaded yet.
        """
        assert self._reader.load_config.is_set(), (
            "load_config() should be called before start_watch()."
        )
        self._reader.splitter = splitter
        self._reader.begin_polling.set()

    @actor_message()
    def kill(self):
        self.killed = True
        self._reader.kill_watcher()

    def _on_worker_died(self, watch_greenlet):
        """
        Greenlet: spawned by the gevent Hub if the etcd watch loop ever
        stops, kills the process.
        """
        _log.critical("Worker greenlet died: %s; exiting.", watch_greenlet)
        sys.exit(1)


class DatastoreReader(TimedGreenlet):
    """
    Greenlet that read from the etcd driver over a socket.

    * Does the initial handshake with the driver, sending it the init
      message.
    * Receives the pre-loaded config from the driver and uses that
      to do Felix's one-off configuration.
    * Sends the relevant config back to the driver.
    * Processes the event stream from the driver, sending it on to
      the splitter.

    This class is similar to the EtcdWatcher class in that it uses
    a PathDispatcher to fan out updates but it doesn't own an etcd
    connection of its own.
    """

    def __init__(self, config, msg_reader, datastore_writer, hosts_ipset,
                 driver_proc):
        super(DatastoreReader, self).__init__()
        self._config = config
        self.hosts_ipset = hosts_ipset
        self._msg_reader = msg_reader
        self._datastore_writer = datastore_writer
        # Whether we've been in sync with etcd at some point.
        self._been_in_sync = False
        # Keep track of the config loaded from etcd so we can spot if it
        # changes.
        self.last_global_config = None
        self.last_host_config = None
        self.my_config_dir = dir_for_per_host_config(self._config.HOSTNAME)
        # Events triggered by the DatastoreAPI Actor to tell us to load the
        # config and start polling.  These are one-way flags.
        self.load_config = Event()
        self.begin_polling = Event()
        # Event that we trigger once the config is loaded.
        self.configured = Event()
        # Polling state initialized at poll start time.
        self.splitter = None
        # Next-hop IP addresses of our hosts, if populated in etcd.
        self.ipv4_by_hostname = {}
        # Forces a resync after the current poll if set.  Safe to set from
        # another thread.  Automatically reset to False after the resync is
        # triggered.
        self.resync_requested = False
        # The Popen object for the driver.
        self._driver_process = driver_proc
        # True if we've been shut down.
        self.killed = False
        # Stats.
        self.read_count = 0
        self.ip_upd_count = 0
        self.ip_remove_count = 0
        self.msgs_processed = 0
        self.last_rate_log_time = monotonic_time()
        self.last_ip_upd_log_time = monotonic_time()
        self.last_ip_remove_log_time = monotonic_time()

    @logging_exceptions
    def _run(self):
        # Don't do anything until we're told to load the config.
        _log.info("Waiting for load_config event...")
        self.load_config.wait()
        _log.info("...load_config set.  Starting driver read %s loop", self)
        # Loop reading from the socket and processing messages.
        self._loop_reading_from_driver()

    def _loop_reading_from_driver(self):
        while True:
            try:
                # Note: self._msg_reader.new_messages() returns iterator so
                # whole for loop must be inside the try.
                for msg_type, msg in self._msg_reader.new_messages(timeout=1):
                    self._dispatch_msg_from_driver(msg_type, msg)
            except SocketClosed:
                _log.critical("The driver process closed its socket, Felix "
                              "must exit.")
                die_and_restart()
            driver_rc = self._driver_process.poll()
            if driver_rc is not None:
                _log.critical("Driver process died with RC = %s.  Felix must "
                              "exit.", driver_rc)
                die_and_restart()

    def _dispatch_msg_from_driver(self, msg_type, msg):
        _log.debug("Dispatching message of type: %s", msg_type)
        if msg_type not in {MSG_TYPE_CONFIG_UPDATE,
                            MSG_TYPE_INIT,
                            MSG_TYPE_STATUS}:
            if not self.begin_polling.is_set():
                _log.info("Non-init message, waiting for begin_polling flag")
            self.begin_polling.wait()

        if msg_type == MSG_TYPE_IPSET_DELTA:
            _stats.increment("IP set delta messages from driver")
            self._on_ipset_delta_msg_from_driver(msg)
        elif msg_type == MSG_TYPE_IPSET_REMOVED:
            _stats.increment("IP set removed messages from driver")
            self._on_ipset_removed_msg_from_driver(msg)
        elif msg_type == MSG_TYPE_IPSET_UPDATE:
            _stats.increment("IP set added messages from driver")
            self._on_ipset_update_msg_from_driver(msg)
        elif msg_type == MSG_TYPE_WL_EP_UPDATE:
            _stats.increment("Workload endpoint update messages from driver")
            self.on_wl_endpoint_update(msg[MSG_KEY_HOSTNAME],
                                       msg[MSG_KEY_ORCH],
                                       msg[MSG_KEY_WORKLOAD_ID],
                                       msg[MSG_KEY_ENDPOINT_ID],
                                       msg.get(MSG_KEY_ENDPOINT))
        elif msg_type == MSG_TYPE_WL_EP_REMOVE:
            _stats.increment("Workload endpoint remove messages from driver")
            self.on_wl_endpoint_update(msg[MSG_KEY_HOSTNAME],
                                       msg[MSG_KEY_ORCH],
                                       msg[MSG_KEY_WORKLOAD_ID],
                                       msg[MSG_KEY_ENDPOINT_ID],
                                       None)
        elif msg_type == MSG_TYPE_HOST_EP_UPDATE:
            _stats.increment("Host endpoint update messages from driver")
            self.on_host_ep_update(msg[MSG_KEY_HOSTNAME],
                                   msg[MSG_KEY_ENDPOINT_ID],
                                   msg.get(MSG_KEY_ENDPOINT))
        elif msg_type == MSG_TYPE_HOST_EP_REMOVE:
            _stats.increment("Host endpoint update remove from driver")
            self.on_host_ep_update(msg[MSG_KEY_HOSTNAME],
                                   msg[MSG_KEY_ENDPOINT_ID],
                                   None)
        elif msg_type == MSG_TYPE_POLICY_UPDATE:
            _stats.increment("Policy update messages from driver")
            self.on_tiered_policy_update(msg[MSG_KEY_TIER_NAME],
                                         msg[MSG_KEY_NAME],
                                         msg.get(MSG_KEY_POLICY))
        elif msg_type == MSG_TYPE_POLICY_REMOVED:
            _stats.increment("Policy update messages from driver")
            self.on_tiered_policy_update(msg[MSG_KEY_TIER_NAME],
                                         msg[MSG_KEY_NAME],
                                         None)
        elif msg_type == MSG_TYPE_PROFILE_UPDATE:
            _stats.increment("Profile update messages from driver")
            self.on_prof_rules_update(msg[MSG_KEY_NAME],
                                      msg.get(MSG_KEY_POLICY))
        elif msg_type == MSG_TYPE_PROFILE_REMOVED:
            _stats.increment("Profile update messages from driver")
            self.on_prof_rules_update(msg[MSG_KEY_NAME], None)
        elif msg_type == MSG_TYPE_CONFIG_UPDATE:
            _stats.increment("Config loaded messages from driver")
            self._on_config_update_from_driver(msg)
        elif msg_type == MSG_TYPE_STATUS:
            _stats.increment("Status messages from driver")
            self._on_status_from_driver(msg)
        else:
            _log.error("Unexpected message %r %s", msg_type, msg)
            #raise RuntimeError("Unexpected message %s" % msg)
        self.msgs_processed += 1
        if self.msgs_processed % MAX_EVENTS_BEFORE_YIELD == 0:
            # Yield to ensure that other actors make progress.  (gevent only
            # yields for us if the socket would block.)  The sleep must be
            # non-zero to work around gevent issue where we could be
            # immediately rescheduled.
            gevent.sleep(0.000001)

    def _on_config_update_from_driver(self, msg):
        """
        Called when we receive a config loaded message from the driver.

        This message is expected once per resync, when the config is
        pre-loaded by the driver.

        On the first call, responds to the driver synchronously with a
        config response.

        If the config has changed since a previous call, triggers Felix
        to die.
        """
        global_config = msg[MSG_KEY_GLOBAL_CONFIG]
        host_config = msg[MSG_KEY_HOST_CONFIG]
        _log.info("Config loaded by driver:\n"
                  "Global: %s\nPer-host: %s",
                  global_config,
                  host_config)
        if self.configured.is_set():
            # We've already been configured.  We don't yet support
            # dynamic config update so instead we check if the config
            # has changed and die if it has.
            _log.info("Checking configuration for changes...")
            if (host_config != self.last_host_config or
                    global_config != self.last_global_config):
                _log.warning("Felix configuration has changed, "
                             "felix must restart.")
                _log.info("Old host config: %s", self.last_host_config)
                _log.info("New host config: %s", host_config)
                _log.info("Old global config: %s",
                          self.last_global_config)
                _log.info("New global config: %s", global_config)
                die_and_restart()
        else:
            # First time loading the config.  Report it to the config
            # object.  Take copies because report_etcd_config is
            # destructive.
            self.last_host_config = host_config.copy()
            self.last_global_config = global_config.copy()
            self._config.report_etcd_config(host_config,
                                            global_config)
            self.configured.set()
            self._datastore_writer.on_config_resolved(async=True)

    def _on_status_from_driver(self, msg):
        """
        Called when we receive a status update from the driver.

        The driver sends us status messages whenever its status changes.
        It moves through these states:

        (1) wait-for-ready (waiting for the global ready flag to become set)
        (2) resync (resyncing with etcd, processing a snapshot and any
            concurrent events)
        (3) in-sync (snapshot processsing complete, now processing only events
            from etcd)

        If the driver falls out of sync with etcd then it will start again
        from (1).

        If the status is in-sync, triggers the relevant processing.
        """
        status = msg[MSG_KEY_STATUS]
        _log.info("etcd driver status changed to %s", status)
        if status == STATUS_IN_SYNC and not self._been_in_sync:
            # We're now in sync, tell the Actors that need to do start-of-day
            # cleanup.
            self.begin_polling.wait()  # Make sure splitter is set.
            self._been_in_sync = True
            self.splitter.on_datamodel_in_sync()
            self._update_hosts_ipset()

    def _on_ipset_update_msg_from_driver(self, msg):
        self.splitter.on_ipset_update(msg[MSG_KEY_IPSET_ID],
                                      msg[MSG_KEY_MEMBERS] or [])

    def _on_ipset_removed_msg_from_driver(self, msg):
        self.splitter.on_ipset_removed(msg[MSG_KEY_IPSET_ID])

    def _on_ipset_delta_msg_from_driver(self, msg):
        _log.debug("IP set delta updates: %v", msg)
        # Output some very coarse stats.
        self.ip_upd_count += 1
        if self.ip_upd_count % 1000 == 0:
            now = monotonic_time()
            delta = now - self.last_ip_upd_log_time
            _log.info("Processed %s IP updates from driver "
                      "%.1f/s", self.ip_upd_count, 1000.0 / delta)
            self.last_ip_upd_log_time = now
        self.splitter.on_ipset_delta_update(msg[MSG_KEY_IPSET_ID],
                                            msg[MSG_KEY_ADDED_IPS] or [],
                                            msg[MSG_KEY_REMOVED_IPS] or [])

    def on_wl_endpoint_update(self, hostname, orchestrator,
                              workload_id, endpoint_id, endpoint):
        """Handler for endpoint updates, passes the update to the splitter."""
        combined_id = WloadEndpointId(hostname, orchestrator, workload_id,
                                      endpoint_id)
        _log.debug("Endpoint %s updated", combined_id)
        _stats.increment("Endpoint created/updated")
        if endpoint is not None:
            common.validate_endpoint(self._config, combined_id, endpoint)
        self.splitter.on_endpoint_update(combined_id, endpoint)

    def on_host_ep_update(self, hostname, endpoint_id, endpoint):
        """Handler for create/update of host endpoint."""
        combined_id = HostEndpointId(hostname, endpoint_id)
        _log.debug("Host iface %s updated", combined_id)
        _stats.increment("Host iface created/updated")
        if endpoint is not None:
            common.validate_host_endpoint(self._config, combined_id, endpoint)
        self.splitter.on_host_ep_update(combined_id, endpoint)

    def on_prof_rules_update(self, profile_id, rules):
        """Handler for rules updates, passes the update to the splitter."""
        _log.debug("Rules for %s set", profile_id)
        _stats.increment("Rules created/updated")
        profile_id = intern(profile_id.encode("utf8"))
        self.splitter.on_rules_update(profile_id, rules)

    def on_tiered_policy_update(self, tier, policy_id, rules):
        _log.debug("Rules for %s/%s set", tier, policy_id)
        _stats.increment("Tiered rules created/updated")
        policy_id = TieredPolicyId(tier, policy_id)
        if rules is not None:
            self.splitter.on_rules_update(policy_id, rules)
            # self.splitter.on_policy_selector_update(policy_id, selector,
            #                                         order)
        else:
            self.splitter.on_rules_update(policy_id, None)
            # self.splitter.on_policy_selector_update(policy_id, None, None)

    # def on_host_ip_set(self, response, hostname):
    #     if not self._config.IP_IN_IP_ENABLED:
    #         _log.debug("Ignoring update to %s because IP-in-IP is disabled",
    #                    response.key)
    #         return
    #     _stats.increment("Host IP created/updated")
    #     ip = parse_host_ip(hostname, response.value)
    #     if ip:
    #         self.ipv4_by_hostname[hostname] = ip
    #     else:
    #         _log.warning("Invalid IP for hostname %s: %s, treating as "
    #                      "deletion", hostname, response.value)
    #         self.ipv4_by_hostname.pop(hostname, None)
    #     self._update_hosts_ipset()
    #
    # def on_host_ip_delete(self, response, hostname):
    #     if not self._config.IP_IN_IP_ENABLED:
    #         _log.debug("Ignoring update to %s because IP-in-IP is disabled",
    #                    response.key)
    #         return
    #     _stats.increment("Host IP deleted")
    #     if self.ipv4_by_hostname.pop(hostname, None):
    #         self._update_hosts_ipset()

    def _update_hosts_ipset(self):
        if not self._been_in_sync:
            _log.debug("Deferring update to hosts ipset until we're in-sync")
            return
        self.hosts_ipset.replace_members(
            frozenset(self.ipv4_by_hostname.values()),
            async=True
        )

    # def on_ipam_v4_pool_set(self, response, pool_id):
    #     _stats.increment("IPAM pool created/updated")
    #     pool = parse_ipam_pool(pool_id, response.value)
    #     self.splitter.on_ipam_pool_updated(pool_id, pool)
    #
    # def on_ipam_v4_pool_delete(self, response, pool_id):
    #     _stats.increment("IPAM pool deleted")
    #     self.splitter.on_ipam_pool_updated(pool_id, None)

    def kill_watcher(self):
        self.killed = True
        if self._driver_process is not None:
            try:
                self._driver_process.send_signal(signal.SIGTERM)
            except OSError:  # Likely already died.
                _log.exception("Failed to kill driver process")
            else:
                self._driver_process.wait()


class DatastoreWriter(Actor):
    """
    Actor that manages and rate-limits the queue of status reports to
    etcd.
    """

    def __init__(self, config, message_writer):
        super(DatastoreWriter, self).__init__()
        self._config = config
        self._start_time = monotonic_time()
        self._writer = message_writer
        self._endpoint_status = {IPV4: {}, IPV6: {}}
        self.config_resolved = False
        self._dirty_endpoints = set()
        self._reporting_allowed = True
        self._status_reporting_greenlet = None

    def _on_actor_started(self):
        self.send_init()

    @logging_exceptions
    def _periodically_report_status(self):
        """
        Greenlet: periodically writes Felix's status into the datastore.

        :return: Does not return, unless reporting disabled.
        """
        interval = self._config.REPORTING_INTERVAL_SECS
        _log.info("Reporting Felix status at interval: %s", interval)
        while True:
            self.update_felix_status(async=True)
            # Jitter by 10% of interval.
            jitter = random.random() * 0.1 * interval
            sleep_time = interval + jitter
            gevent.sleep(sleep_time)

    def send_init(self):
        # Give the driver its config.
        self._writer.send_message(
            MSG_TYPE_INIT,
            {
                MSG_KEY_ETCD_URLS: [self._config.ETCD_SCHEME + "://" +
                                    addr for addr in self._config.ETCD_ADDRS],
                MSG_KEY_HOSTNAME: self._config.HOSTNAME,
                MSG_KEY_KEY_FILE: self._config.ETCD_KEY_FILE,
                MSG_KEY_CERT_FILE: self._config.ETCD_CERT_FILE,
                MSG_KEY_CA_FILE: self._config.ETCD_CA_FILE,
            }
        )

    @actor_message()
    def on_config_resolved(self):
        # Config now fully resolved, inform the driver.
        self.config_resolved = True
        driver_log_file = self._config.DRIVERLOGFILE
        self._writer.send_message(
            MSG_TYPE_CONFIG,
            {
                MSG_KEY_LOG_FILE: driver_log_file,
                MSG_KEY_SEV_FILE: self._config.LOGLEVFILE,
                MSG_KEY_SEV_SCREEN: self._config.LOGLEVSCR,
                MSG_KEY_SEV_SYSLOG: self._config.LOGLEVSYS,
                MSG_KEY_PROM_PORT:
                    self._config.PROM_METRICS_DRIVER_PORT if
                    self._config.PROM_METRICS_ENABLED else None
            }
        )

        if self._config.REPORTING_INTERVAL_SECS > 0:
            self._status_reporting_greenlet = TimedGreenlet(
                self._periodically_report_status
            )
            self._status_reporting_greenlet.link_exception(
                self._on_worker_died
            )
            self._status_reporting_greenlet.start()

    @actor_message()
    def on_endpoint_status_changed(self, endpoint_id, ip_type, status):
        assert isinstance(endpoint_id, EndpointId)
        if status is not None:
            _stats.increment("Endpoint status updated")
            self._endpoint_status[ip_type][endpoint_id] = status
        else:
            _stats.increment("Endpoint status deleted")
            self._endpoint_status[ip_type].pop(endpoint_id, None)
        self._mark_endpoint_dirty(endpoint_id)

    @actor_message()
    def update_felix_status(self):
        """Sends Felix's status to the backend driver."""
        time_formatted = iso_utc_timestamp()
        uptime = monotonic_time() - self._start_time
        self._writer.send_message(
            MSG_TYPE_FELIX_STATUS,
            {
                MSG_KEY_TIME: time_formatted,
                MSG_KEY_UPTIME: uptime,
            }
        )

    def _mark_endpoint_dirty(self, endpoint_id):
        assert isinstance(endpoint_id, EndpointId)
        _log.debug("Marking endpoint %s dirty", endpoint_id)
        self._dirty_endpoints.add(endpoint_id)

    def _finish_msg_batch(self, batch, results):
        if not self.config_resolved:
            _log.debug("Still waiting for config, skipping endpoint status "
                       "updates")
            return

        if not self._config.REPORT_ENDPOINT_STATUS:
            _log.debug("Endpoint reporting disabled, clearing any state.")
            self._endpoint_status[IPV4].clear()
            self._endpoint_status[IPV6].clear()
            self._dirty_endpoints.clear()
            return

        for ep_id in self._dirty_endpoints:
            status_v4 = self._endpoint_status[IPV4].get(ep_id)
            status_v6 = self._endpoint_status[IPV6].get(ep_id)
            status = combine_statuses(status_v4, status_v6)
            self._write_endpoint_status(ep_id, status)

        self._dirty_endpoints.clear()

    def _write_endpoint_status(self, ep_id, status):
        _stats.increment("Per-port status report writes")
        if isinstance(ep_id, WloadEndpointId):
            if status is not None:
                self._writer.send_message(
                    MSG_TYPE_WL_ENDPOINT_STATUS,
                    {
                        MSG_KEY_HOSTNAME: ep_id.host,
                        MSG_KEY_ORCH: ep_id.orchestrator,
                        MSG_KEY_WORKLOAD_ID: ep_id.workload,
                        MSG_KEY_ENDPOINT_ID: ep_id.endpoint,
                        MSG_KEY_STATUS: status["status"]
                    }
                )
            else:
                self._writer.send_message(
                    MSG_TYPE_WL_ENDPOINT_STATUS_REMOVE,
                    {
                        MSG_KEY_HOSTNAME: ep_id.host,
                        MSG_KEY_ORCH: ep_id.orchestrator,
                        MSG_KEY_WORKLOAD_ID: ep_id.workload,
                        MSG_KEY_ENDPOINT_ID: ep_id.endpoint
                    }
                )
        else:
            if status is not None:
                self._writer.send_message(
                    MSG_TYPE_HOST_ENDPOINT_STATUS,
                    {
                        MSG_KEY_HOSTNAME: ep_id.host,
                        MSG_KEY_ENDPOINT_ID: ep_id.endpoint,
                        MSG_KEY_STATUS: status["status"]
                    }
                )
            else:
                self._writer.send_message(
                    MSG_TYPE_HOST_ENDPOINT_STATUS_REMOVE,
                    {
                        MSG_KEY_HOSTNAME: ep_id.host,
                        MSG_KEY_ENDPOINT_ID: ep_id.endpoint
                    }
                )

    def _on_worker_died(self, watch_greenlet):
        """
        Greenlet: spawned by the gevent Hub if the worker ever stops, kills
        the process.
        """
        _log.critical("Worker greenlet died: %s; exiting.",
                      watch_greenlet)
        sys.exit(1)


def combine_statuses(status_a, status_b):
    """
    Combines a pair of status reports for the same interface.

    If one status is None, the other is returned.  Otherwise, the worst
    status wins.
    """
    if not status_a:
        return status_b
    if not status_b:
        return status_a
    a = status_a["status"]
    b = status_b["status"]
    if a == ENDPOINT_STATUS_ERROR or b == ENDPOINT_STATUS_ERROR:
        return {"status": ENDPOINT_STATUS_ERROR}
    elif a == ENDPOINT_STATUS_DOWN or b == ENDPOINT_STATUS_DOWN:
        return {"status": ENDPOINT_STATUS_DOWN}
    else:
        return {"status": ENDPOINT_STATUS_UP}


def die_and_restart():
    # Sleep so that we can't die more than 5 times in 10s even if someone is
    # churning the config.  This prevents our upstart/systemd jobs from giving
    # up on us.
    gevent.sleep(2)
    # Use a failure code to tell systemd that we expect to be restarted.  We
    # use os._exit() because it is bullet-proof.
    os._exit(1)
