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
from calico.common import ValidationFailed, KNOWN_RULE_KEYS
from calico.datamodel_v1 import (VERSION_DIR, READY_KEY, CONFIG_DIR,
                                 RULES_KEY_RE, TAGS_KEY_RE, ENDPOINT_KEY_RE,
                                 dir_for_per_host_config,
                                 dir_for_host,
                                 PROFILE_DIR, HOST_DIR, EndpointInfo,
                                 delete_action,
                                 DELETED_NONE,
                                 DELETED_ALL,
                                 DELETED_PROFILE,
                                 DELETED_TAGS,
                                 DELETED_RULES,
                                 DELETED_ENDPOINT,
                                 DELETED_WORKLOAD,
                                 DELETED_ORCHESTRATOR,
                                 DELETED_HOST)

from calico.felix.actor import Actor, actor_message

_log = logging.getLogger(__name__)


RETRY_DELAY = 5


class EtcdWatcher(Actor):
    def __init__(self, config):
        super(EtcdWatcher, self).__init__()
        self.config = config
        self.client = None
        self.my_config_dir = dir_for_per_host_config(self.config.HOSTNAME)

        # Set of EndpointInfo objects on each host.
        self.endpoints_by_host = defaultdict(set)

        # Update splitter. Not available until watch_etcd is called.
        self._update_splitter = None

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
        self._update_splitter = update_splitter

        while True:
            _log.info("Reconnecting and loading snapshot from etcd...")
            self._reconnect(copy_cluster_id=False)
            self.wait_for_ready()

            # Load initial dump from etcd.  First just get all the endpoints
            # and profiles by id.  The response contains a generation ID
            # allowing us to then start polling for updates without missing
            # any.
            initial_dump = self.client.read(VERSION_DIR, recursive=True)
            _log.info("Loaded snapshot from etcd cluster %s, parsing it...",
                      self.client.expected_cluster_id)
            rules_by_id = {}
            tags_by_id = {}
            endpoints_by_ep_info = {}
            still_ready = False

            self.endpoints_by_host.clear()

            for child in initial_dump.children:
                profile_id, rules = parse_if_rules(child)
                if profile_id:
                    rules_by_id[profile_id] = rules
                    continue
                profile_id, tags = parse_if_tags(child)
                if profile_id:
                    tags_by_id[profile_id] = tags
                    continue
                endpoint_info, endpoint = parse_if_endpoint(self.config, child)
                if endpoint_info and endpoint:
                    endpoints_by_ep_info[endpoint_info] = endpoint
                    self.endpoints_by_host[endpoint_info.host].add(endpoint_info)
                    continue

                # Double-check the flag hasn't changed since we read it before.
                if child.key == READY_KEY:
                    if child.value == "true":
                        still_ready = True
                    else:
                        _log.warning("Aborting resync because ready flag was"
                                     "unset since we read it.")
                        continue

            if not still_ready:
                _log.warn("Aborting resync; ready flag no longer present.")
                continue

            # Actually apply the snapshot. This does not return anything, but
            # just sends the relevant messages to the relevant threads to make
            # all the processing occur.
            _log.info("Snapshot parsed, passing to update splitter")
            update_splitter.apply_snapshot(rules_by_id,
                                           tags_by_id,
                                           endpoints_by_ep_info,
                                           async=False)

            # These read only objects are no longer required, so tidy them up.
            del rules_by_id
            del tags_by_id
            del endpoints_by_ep_info

            # On first call, the etcd_index seems to be the high-water mark
            # for the data returned whereas the modified index just tells us
            # when the key was modified.
            _log.info("Starting polling for updates from etcd.  Initial etcd "
                      "index: %s.", initial_dump.etcd_index)
            next_etcd_index = initial_dump.etcd_index + 1
            del initial_dump
            continue_polling = True
            while continue_polling:
                response = None
                try:
                    _log.debug("About to wait for etcd update %s",
                               next_etcd_index)
                    response = self.client.read(VERSION_DIR,
                                                wait=True,
                                                waitIndex=next_etcd_index,
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
                    continue_polling = False
                except EtcdException as e:
                    # Sadly, python-etcd doesn't have a dedicated exception
                    # for the "no more machines in cluster" error. Parse the
                    # message:
                    msg = (e.message or "unknown").lower()
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
                        continue_polling = False
                    # TODO: should we do a backoff here?
                    gevent.sleep(1)
                    self._reconnect()
                except:
                    _log.exception("Unexpected exception during etcd poll")
                    raise

                if not response:
                    _log.debug("Failed to get a response from etcd.")
                    continue

                # Since we're polling on a subtree, we can't just increment
                # the index, we have to look at the modifiedIndex to spot if
                # we've skipped a lot of updates.
                next_etcd_index = max(next_etcd_index,
                                      response.modifiedIndex) + 1

                if response.action == "delete":
                    # Something has been deleted - figure out what we need to
                    # do and do it.
                    _log.info("Deletion of object %s", response.key)
                    continue_polling = self._process_delete(response)

                    # We have now processed all of the actions.
                    continue

                profile_id, rules = parse_if_rules(response)
                if profile_id:
                    _log.info("Scheduling profile update %s", profile_id)
                    update_splitter.on_rules_update(profile_id, rules,
                                                    async=False)
                    continue
                profile_id, tags = parse_if_tags(response)
                if profile_id:
                    _log.info("Scheduling tags update %s", profile_id)
                    update_splitter.on_tags_update(profile_id, tags,
                                                   async=False)
                    continue
                ep_info, endpoint = parse_if_endpoint(self.config,
                                                      response)
                if ep_info:
                    _log.info("Scheduling endpoint update %s", ep_info)
                    update_splitter.on_endpoint_update(ep_info, endpoint,
                                                       async=False)
                    self.endpoints_by_host[ep_info.host].add(ep_info)
                    continue

                if response.key == READY_KEY:
                    if response.value != "true":
                        _log.warning("DB became unready, triggering a resync")
                        continue_polling = False
                    continue

                _log.debug("Response action: %s, key: %s",
                           response.action, response.key)
                if (response.action not in ("set", "create") and
                        any((response.key.startswith(pfx) for pfx in
                             PREFIXES_TO_RESYNC_ON_CHANGE))):
                    # Catch deletions of whole directories or other operations
                    # that we're not expecting.
                    _log.warning("Unexpected event: %s; triggering resync.",
                                 response)
                if response.key.startswith(CONFIG_DIR):
                    _log.warning("Global config changed but we don't "
                                 "yet support dynamic config: %s",
                                 response)
                if response.key.startswith(self.my_config_dir):
                    _log.warning("Config for this felix changed but we don't "
                                 "yet support dynamic config: %s",
                                 response)

    def _process_delete(self, response):
        """
        Handle a deletion.

        :param response: Response received
        :returns whether or not to continue polling.
        """
        # List of deleted endpoints - may not be any.
        deleted_ep_info = []
        continue_polling = True

        del_action = delete_action(response.key)

        if del_action['type'] == DELETED_NONE:
            # We don't care about this key.
            _log.debug("Ignore deletion of %s",
                         response.key)
        elif del_action['type'] == DELETED_ALL:
            _log.warning("Major deletion (%s) - resync all data",
                         response.key)
            continue_polling = False
        elif del_action['type'] == DELETED_PROFILE:
            _log.info("Delete for whole profile %s", del_action['profile'])
            self._update_splitter.on_rules_update(del_action['profile'],
                                                  None,
                                                  async=True)
            self._update_splitter.on_tags_update(del_action['profile'],
                                                 None,
                                                 async=True)
        elif del_action['type'] == DELETED_TAGS:
            _log.info("Delete for tags in profile %s", del_action['profile'])
            self._update_splitter.on_tags_update(del_action['profile'],
                                                 None,
                                                 async=True)
        elif del_action['type'] == DELETED_RULES:
            _log.info("Delete for rules in profile %s", del_action['profile'])
            self._update_splitter.on_rules_update(del_action['profile'],
                                                  None,
                                                  async=True)
        elif del_action['type'] == DELETED_ENDPOINT:
            deleted_ep_info.append(
                EndpointInfo(del_action['host'],
                             del_action['orchestrator'],
                             del_action['workload'],
                             del_action['endpoint']))
        else:
            assert (del_action['type'] in (DELETED_WORKLOAD,
                                           DELETED_ORCHESTRATOR,
                                           DELETED_HOST))

            orch = del_action.get('orchestrator')
            work = del_action.get('workload')

            for ep_info in self.endpoints_by_host[del_action['host']]:
                if ((not orch or orch == ep_info.orchestrator) and
                    (not work or work == ep_info.workload)):
                    deleted_ep_info.append(ep_info)

        for ep_info in deleted_ep_info:
            _log.info("Scheduling endpoint deletion %s", ep_info)
            host = del_action['host']
            self._update_splitter.on_endpoint_update(ep_info, None, async=True)
            self.endpoints_by_host[host].remove(ep_info)
            if not self.endpoints_by_host[host]:
                # All endpoints removed from this host - forget about it.
                del self.endpoints_by_host[host]

        return continue_polling

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
        endpoint = json_decoder.decode(etcd_node.value)
        try:
            common.validate_endpoint(config, endpoint)
        except ValidationFailed as e:
            _log.warning("Validation failed for endpoint %s, treating as "
                         "missing: %s", endpoint_id, e.message)
            endpoint = None
        else:
            _log.debug("Validated endpoint : %s", endpoint)
        return EndpointInfo(host, orch, workload_id, endpoint_id), endpoint
    return None, None


def parse_if_rules(etcd_node):
    m = RULES_KEY_RE.match(etcd_node.key)
    if m:
        # Got some rules.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            rules = None
        else:
            rules = json_decoder.decode(etcd_node.value)
            rules["id"] = profile_id
            try:
                common.validate_rules(rules)
            except ValidationFailed:
                _log.exception("Validation failed for profile %s rules: %s",
                               profile_id, rules)
                return profile_id, None

        _log.debug("Found rules for profile %s : %s", profile_id, rules)

        return profile_id, rules
    return None, None


def parse_if_tags(etcd_node):
    m = TAGS_KEY_RE.match(etcd_node.key)
    if m:
        # Got some tags.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            tags = None
        else:
            tags = json_decoder.decode(etcd_node.value)
            try:
                common.validate_tags(tags)
            except ValidationFailed:
                _log.exception("Validation failed for profile %s tags : %s",
                               profile_id, tags)
                return profile_id, None

        _log.debug("Found tags for profile %s : %s", profile_id, tags)

        return profile_id, tags
    return None, None
