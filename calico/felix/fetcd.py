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
felix.fetcd
~~~~~~~~~~~~

Etcd polling functions.
"""
from collections import defaultdict
from socket import timeout as SocketTimeout
from etcd import (EtcdException, EtcdClusterIdChanged, EtcdKeyNotFound,
                  EtcdEventIndexCleared)
import etcd
import httplib
import json
import logging
import gevent
from urllib3 import Timeout
import urllib3.exceptions
from urllib3.exceptions import ReadTimeoutError, ConnectTimeoutError

from calico import common
from calico.common import ValidationFailed
from calico.datamodel_v1 import (VERSION_DIR, READY_KEY, CONFIG_DIR,
                                 RULES_KEY_RE, TAGS_KEY_RE, ENDPOINT_KEY_RE,
                                 dir_for_per_host_config,
                                 PROFILE_DIR, HOST_DIR, EndpointId)
from calico.felix.actor import Actor, actor_message

_log = logging.getLogger(__name__)


RETRY_DELAY = 5

# If we see an unhandled event (e.g. a directory deletion) for keys in any of
# these prefixes, we'll abort our polling and resync.
PREFIXES_TO_RESYNC_ON_CHANGE = [
    READY_KEY,
    PROFILE_DIR,
    HOST_DIR,
]

# Map etcd event actions to the effects we care about.
ACTION_MAPPING = {
    "set": "set",
    "compareAndSwap": "set",
    "create": "set",
    "update": "set",

    "delete": "delete",
    "compareAndDelete": "delete",
    "expire": "delete",
}


class Capture(object):
    def __init__(self, name):
        self.name = name


class EtcdWatcher(Actor):
    def __init__(self, config):
        super(EtcdWatcher, self).__init__()
        self.config = config
        self.client = None
        self.my_config_dir = dir_for_per_host_config(self.config.HOSTNAME)

        # Initialized at poll start time.
        self.splitter = None
        self.next_etcd_index = None

        # Cache of known endpoints, used to resolve deletions of whole
        # directory trees.
        self.endpoint_ids_per_host = defaultdict(set)

        self.handlers = {
            "delete": self.force_resync,

            "Ready": {
                "set": self.on_ready,
                "delete": self.force_resync,
            },

            "policy": {
                "delete": self.force_resync,

                "profile": {
                    "delete": self.force_resync,

                    "capture": ("profile_id",  {
                        "delete": self.on_profile_delete,

                        "tags": {
                            "delete": self.on_tags_delete,
                            "set": self.on_tags_set,
                        },

                        "rules": {
                            "delete": self.on_rules_delete,
                            "set": self.on_rules_set,
                        }
                    })
                }
            },

            "host": {
                "delete": self.force_resync,

                "capture": ("hostname",  {
                    "delete": self.on_host_delete,

                    "workload": {
                        "delete": self.on_host_delete,

                        "capture": ("orchestrator",  {
                            "delete": self.on_orch_delete,

                            "capture": ("workload_id",  {
                                "delete": self.on_workload_delete,

                                "endpoint": {
                                    "delete": self.on_workload_delete,

                                    "capture": ("endpoint_id",  {
                                        "delete": self.on_endpoint_delete,
                                        "set": self.on_endpoint_set
                                    })
                                }
                            })
                        })
                    }
                })
            }
        }

    @actor_message()
    def load_config(self):
        _log.info("Waiting for etcd to be ready and for config to be present.")
        configured = False
        while not configured:
            self._reconnect()
            self.wait_for_ready()
            try:
                global_cfg = self.client.read(CONFIG_DIR)
                global_dict = _build_config_dict(global_cfg)

                try:
                    host_cfg = self.client.read(self.my_config_dir)
                    host_dict = _build_config_dict(host_cfg)
                except EtcdKeyNotFound:
                    # It is not an error for there to be no per-host config;
                    # default to empty.
                    _log.info("No configuration overrides for this node")
                    host_dict = {}
            except (EtcdKeyNotFound, EtcdException) as e:
                # Note: we don't log the stack trace because it's too spammy
                # and adds little.
                _log.error("Failed to read config. etcd may be down or the"
                           "data model may not be ready: %r. Will retry.", e)
                gevent.sleep(RETRY_DELAY)
                continue

            self.config.report_etcd_config(host_dict, global_dict)
            configured = True

    @actor_message()
    def wait_for_ready(self):
        _log.info("Waiting for etcd to be ready...")
        ready = False
        while not ready:
            try:
                db_ready = self.client.read(READY_KEY,
                                            timeout=10).value
            except EtcdKeyNotFound:
                _log.warn("Ready flag not present in etcd; felix will pause "
                          "updates until the orchestrator sets the flag.")
                db_ready = "false"
            except EtcdException as e:
                # Note: we don't log the
                _log.error("Failed to retrieve ready flag from etcd (%r). "
                           "Felix will not receive updates until the "
                           "connection to etcd is restored.", e)
                db_ready = "false"

            if db_ready == "true":
                _log.info("etcd is ready.")
                ready = True
            else:
                _log.info("etcd not ready.  Will retry.")
                gevent.sleep(RETRY_DELAY)
                continue

    def _reconnect(self, copy_cluster_id=True):
        _log.info("(Re)connecting to etcd...")
        etcd_addr = self.config.ETCD_ADDR
        if ":" in etcd_addr:
            host, port = etcd_addr.split(":")
            port = int(port)
        else:
            host = etcd_addr
            port = 4001
        if self.client and copy_cluster_id:
            old_cluster_id = self.client.expected_cluster_id
            _log.info("Old etcd cluster ID was %s.", old_cluster_id)
        else:
            old_cluster_id = None
        self.client = etcd.Client(host=host, port=port,
                                  expected_cluster_id=old_cluster_id)

    @actor_message()
    def watch_etcd(self, update_splitter):
        """
        Loads the snapshot from etcd and then monitors etcd for changes.
        Posts events to the UpdateSplitter.

        :returns: Does not return.
        """
        self.splitter = update_splitter
        while True:
            _log.info("Reconnecting and loading snapshot from etcd...")
            self._reconnect(copy_cluster_id=False)
            self.wait_for_ready()

            try:
                # Load initial dump from etcd.  First just get all the
                # endpoints and profiles by id.  The response contains a
                # generation ID allowing us to then start polling for updates
                # without missing any.
                self.load_initial_dump()
                while True:
                    # Wait for something to change.
                    response = self._wait_for_etcd_event()

                    # Extract parts of the key following /calico/v1/
                    key_parts = response.key.strip("/").split("/")[2:]

                    # Actually deal with this event.
                    self.handle_event(key_parts, response, self.handlers)
            except ResyncRequired:
                _log.info("Polling aborted, doing resync.")

    def load_initial_dump(self):
        """
        Loads a snapshot from etcd and passes it to the update splitter.

        :raises ResyncRequired: if the Ready flag is not set in the snapshot.
        """
        initial_dump = self.client.read(VERSION_DIR, recursive=True)
        _log.info("Loaded snapshot from etcd cluster %s, parsing it...",
                  self.client.expected_cluster_id)
        rules_by_id = {}
        tags_by_id = {}
        endpoints_by_id = {}
        self.endpoint_ids_per_host.clear()
        still_ready = False
        for child in initial_dump.children:
            profile_id, rules = parse_if_rules(child)
            if profile_id:
                rules_by_id[profile_id] = rules
                continue
            profile_id, tags = parse_if_tags(child)
            if profile_id:
                tags_by_id[profile_id] = tags
                continue
            endpoint_id, endpoint = parse_if_endpoint(self.config, child)
            if endpoint_id and endpoint:
                endpoints_by_id[endpoint_id] = endpoint
                self.endpoint_ids_per_host[endpoint_id.host].add(endpoint_id)
                continue

            # Double-check the flag hasn't changed since we read it before.
            if child.key == READY_KEY:
                if child.value == "true":
                    still_ready = True
                else:
                    _log.warning("Aborting resync because ready flag was"
                                 "unset since we read it.")
                    raise ResyncRequired()

        if not still_ready:
            _log.warn("Aborting resync; ready flag no longer present.")
            raise ResyncRequired()

        # Actually apply the snapshot. This does not return anything, but
        # just sends the relevant messages to the relevant threads to make
        # all the processing occur.
        _log.info("Snapshot parsed, passing to update splitter")
        self.splitter.apply_snapshot(rules_by_id,
                                     tags_by_id,
                                     endpoints_by_id,
                                     async=False)
        # The etcd_index is the high-water-mark for the snapshot, record that
        # we want to poll starting at the next index.
        self.next_etcd_index = initial_dump.etcd_index + 1

    def _wait_for_etcd_event(self):
        """
        Polls etcd until something changes.

        Retries on read timeouts and other non-fatal errors.

        :returns: The etcd response object for the change.
        :raises ResyncRequired: If we get out of sync with etcd or hit
            a fatal error.
        """
        response = None
        while not response:
            try:
                _log.debug("About to wait for etcd update %s",
                           self.next_etcd_index)
                response = self.client.read(VERSION_DIR,
                                            wait=True,
                                            waitIndex=self.next_etcd_index,
                                            recursive=True,
                                            timeout=Timeout(connect=10,
                                                            read=90),
                                            check_cluster_uuid=True)
                _log.debug("etcd response: %r", response)
            except (ReadTimeoutError, SocketTimeout) as e:
                # This is expected when we're doing a poll and nothing
                # happened. socket timeout doesn't seem to be caught by
                # urllib3 1.7.1.  Simply reconnect.
                _log.debug("Read from etcd timed out (%r), retrying.", e)
                # Force a reconnect to ensure urllib3 doesn't recycle the
                # connection.  (We were seeing this with urllib3 1.7.1.)
                self._reconnect()
            except (ConnectTimeoutError,
                    urllib3.exceptions.HTTPError,
                    httplib.HTTPException):
                _log.warning("Low-level HTTP error, reconnecting to "
                             "etcd.", exc_info=True)
                self._reconnect()
            except (EtcdClusterIdChanged, EtcdEventIndexCleared) as e:
                _log.warning("Out of sync with etcd (%r).  Reconnecting "
                             "for full sync.", e)
                raise ResyncRequired()
            except EtcdException as e:
                # Sadly, python-etcd doesn't have a dedicated exception
                # for the "no more machines in cluster" error. Parse the
                # message:
                msg = (e.message or "unknown").lower()
                # Limit our retry rate in case etcd is down.
                gevent.sleep(1)
                if "no more machines" in msg:
                    # This error comes from python-etcd when it can't
                    # connect to any servers.  When we retry, it should
                    # reconnect.
                    # TODO: We should probably limit retries here and die
                    # That'd recover from errors caused by resource
                    # exhaustion/leaks.
                    _log.error("Connection to etcd failed, will retry.")
                else:
                    # Assume any other errors are fatal to our poll and
                    # do a full resync.
                    _log.exception("Unknown etcd error %r; doing resync.",
                                   e.message)
                    self._reconnect()
                    raise ResyncRequired()
            except:
                _log.exception("Unexpected exception during etcd poll")
                raise

        # Since we're polling on a subtree, we can't just increment
        # the index, we have to look at the modifiedIndex to spot
        # if we've skipped a lot of updates.
        self.next_etcd_index = max(self.next_etcd_index,
                                   response.modifiedIndex) + 1
        return response

    def handle_event(self, key_parts, response, handlers,  captures=None):
        if captures is None:
            captures = {}
        if not key_parts:
            # We've reached the end of the key.
            action = ACTION_MAPPING.get(response.action)
            if action in handlers:
                _log.debug("Found handler for event %s for %s, captures: %s",
                           action, response.key, captures)
                handlers[action](response, **captures)
            else:
                _log.debug("No handler for event %s on %s",
                           action, response.key)
        else:
            next_part = key_parts[0]
            key_parts = key_parts[1:]
            if "capture" in handlers:
                capture_name, sub_handler = handlers["capture"]
                captures[capture_name] = next_part
            elif next_part in handlers:
                sub_handler = handlers[next_part]
            else:
                _log.debug("No matching sub-handler for %s", response.key)
                return
            self.handle_event(key_parts, response, sub_handler,
                              captures=captures)

    def force_resync(self, response, **kwargs):
        raise ResyncRequired()

    def on_ready(self, response):
        if response.value != "true":
            raise ResyncRequired()

    def on_endpoint_set(self, response, hostname, orchestrator,
                           workload_id, endpoint_id):
        combined_id = EndpointId(hostname, orchestrator, workload_id,
                                 endpoint_id)
        _log.debug("Endpoint %s updated", combined_id)
        self.endpoint_ids_per_host[combined_id.host].add(combined_id)
        endpoint = parse_endpoint(self.config, endpoint_id, response.value)
        self.splitter.on_endpoint_update(combined_id, endpoint)

    def on_endpoint_delete(self, response, hostname, orchestrator,
                           workload_id, endpoint_id):
        combined_id = EndpointId(hostname, orchestrator, workload_id,
                                 endpoint_id)
        _log.debug("Endpoint %s deleted", combined_id)
        self.endpoint_ids_per_host[combined_id.host].discard(combined_id)
        if not self.endpoint_ids_per_host[combined_id.host]:
            del self.endpoint_ids_per_host[combined_id.host]
        self.splitter.on_endpoint_update(combined_id, None)

    def on_rules_set(self, response, profile_id):
        _log.debug("Rules for %s set", profile_id)
        rules = parse_rules(profile_id, response.value)
        self.splitter.on_rules_update(profile_id, rules)

    def on_rules_delete(self, response, profile_id):
        _log.debug("Rules for %s deleted", profile_id)
        self.splitter.on_rules_update(profile_id, None)

    def on_tags_set(self, response, profile_id):
        _log.debug("Tags for %s set", profile_id)
        rules = parse_tags(profile_id, response.value)
        self.splitter.on_tags_update(profile_id, rules)

    def on_tags_delete(self, response, profile_id):
        _log.debug("Tags for %s deleted", profile_id)
        self.splitter.on_tags_update(profile_id, None)

    def on_profile_delete(self, response, profile_id):
        # Fake deletes for the rules and tags.
        _log.debug("Whole profile %s deleted", profile_id)
        self.splitter.on_rules_update(profile_id, None)
        self.splitter.on_tags_update(profile_id, None)

    def on_host_delete(self, response, hostname):
        ids_on_that_host = self.endpoint_ids_per_host.pop(hostname, set())
        _log.info("Host %s deleted, removing %d endpoints",
                  hostname, len(ids_on_that_host))
        for endpoint_id in ids_on_that_host:
            self.splitter.on_endpoint_update(endpoint_id, None, async=True)

    def on_orch_delete(self, response, hostname, orchestrator):
        _log.info("Orchestrator dir %s/%s deleted, removing contained hosts",
                  hostname, orchestrator)
        for endpoint_id in list(self.endpoint_ids_per_host[hostname]):
            if endpoint_id.orchestrator == orchestrator:
                self.splitter.on_endpoint_update(endpoint_id, None, async=True)
                self.endpoint_ids_per_host[hostname].discard(endpoint_id)
        if not self.endpoint_ids_per_host[hostname]:
            del self.endpoint_ids_per_host[hostname]

    def on_workload_delete(self, response, hostname, orchestrator,
                           workload_id):
        _log.info("Workload dir %s/%s/%s deleted, removing contained hosts",
                  hostname, orchestrator, workload_id)
        for endpoint_id in list(self.endpoint_ids_per_host[hostname]):
            if (endpoint_id.orchestrator == orchestrator and
                    endpoint_id.workload == workload_id):
                self.splitter.on_endpoint_update(endpoint_id, None, async=True)
                self.endpoint_ids_per_host[hostname].discard(endpoint_id)
        if not self.endpoint_ids_per_host[hostname]:
            del self.endpoint_ids_per_host[hostname]


def _build_config_dict(cfg_node):
    """
    Updates the config dict provided from the given etcd node, which
    should point at a config directory.
    """
    config_dict = {}
    for child in cfg_node.children:
        key = child.key.rsplit("/").pop()
        value = str(child.value)
        config_dict[key] = value
    return config_dict


# Intern JSON keys as we load them to reduce occupancy.
def intern_dict(d):
    return dict((intern(str(k)), v) for k, v in d.iteritems())
json_decoder = json.JSONDecoder(object_hook=intern_dict)


def parse_if_endpoint(config, etcd_node):
    m = ENDPOINT_KEY_RE.match(etcd_node.key)
    if m:
        # Got an endpoint.
        host = m.group("hostname")
        orch = m.group("orchestrator")
        workload_id = m.group("workload_id")
        endpoint_id = m.group("endpoint_id")
        if etcd_node.action == "delete":
            _log.debug("Found deleted endpoint %s", endpoint_id)
            endpoint = None
        else:
            endpoint = parse_endpoint(config, endpoint_id, etcd_node.value)
        return EndpointId(host, orch, workload_id, endpoint_id), endpoint
    return None, None


def parse_endpoint(config, endpoint_id, raw_json):
    endpoint = json_decoder.decode(raw_json)
    try:
        common.validate_endpoint(config, endpoint)
    except ValidationFailed as e:
        _log.warning("Validation failed for endpoint %s, treating as "
                     "missing: %s", endpoint_id, e.message)
        endpoint = None
    else:
        _log.debug("Validated endpoint : %s", endpoint)
    return endpoint


def parse_if_rules(etcd_node):
    m = RULES_KEY_RE.match(etcd_node.key)
    rules = None
    if m:
        # Got some rules.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            rules = None
        else:
            rules = parse_rules(profile_id, etcd_node.value)
        return profile_id, rules
    return None, None


def parse_rules(profile_id, raw_json):
    rules = json_decoder.decode(raw_json)
    rules["id"] = profile_id
    try:
        common.validate_rules(rules)
    except ValidationFailed:
        _log.exception("Validation failed for profile %s rules: %s",
                       profile_id, rules)
        return None
    else:
        return rules


def parse_if_tags(etcd_node):
    m = TAGS_KEY_RE.match(etcd_node.key)
    if m:
        # Got some tags.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            tags = None
        else:
            tags = parse_tags(profile_id, etcd_node.value)
        return profile_id, tags
    return None, None


def parse_tags(profile_id, raw_json):
    tags = json_decoder.decode(raw_json)
    try:
        common.validate_tags(tags)
    except ValidationFailed:
        _log.exception("Validation failed for profile %s tags : %s",
                       profile_id, tags)
        return None
    else:
        return tags


class ResyncRequired(Exception):
    pass