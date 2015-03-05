# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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
import json
import logging
import socket
from etcd import EtcdException
import etcd
import re

_log = logging.getLogger(__name__)


# etcd path regexes
PROFILE_RE = re.compile(
    r'^/calico/network/profile/(?P<profile_id>[^/]+)/policy')
ENDPOINT_RE = re.compile(
    r'^/calico/host/(?P<hostname>[^/]+)/endpoint/(?P<endpoint_id>[^/]+)')


def watch_etcd(update_sequencer):
    """
    Loads the snapshot from etcd and then monitors etcd for changes.
    Posts events to the UpdateSequencer.

    Intended to be used as a greenlet.  Intended to be restarted if
    it raises an exception.

    :returns: Does not return.
    :raises EtcdException: if a read from etcd fails and we may fall out of
            sync.
    """
    client = etcd.Client()

    # Load initial dump from etcd.  First just get all the endpoints and
    # profiles by id.  The response contains a generation ID allowing us
    # to then start polling for updates without missing any.
    initial_dump = client.read("/calico/", recursive=True)
    profiles_by_id = {}
    endpoints_by_id = {}
    for child in initial_dump.children:
        profile_id, profile = parse_if_profile(child)
        if profile_id:
            profiles_by_id[profile_id] = profile
            continue
        endpoint_id, endpoint = parse_if_endpoint(child)
        if endpoint_id:
            endpoints_by_id[endpoint_id] = endpoint
            continue

    # Actually apply the snapshot.  The UpdateSequencer will apply deltas as
    # appropriate.  Grab the future in case it raises an error.
    f_apply_snap = update_sequencer.apply_snapshot(profiles_by_id,
                                                   endpoints_by_id,
                                                   async=True)
    del profiles_by_id
    del endpoints_by_id

    last_etcd_index = initial_dump.etcd_index
    last_value = None
    last_key = None
    while True:
        if f_apply_snap and f_apply_snap.ready():
            # Snapshot application finished, check for exceptions.
            _log.info("Snapshot application returned, checking for errors.")
            f_apply_snap.get_nowait()
            f_apply_snap = None

        # TODO Handle deletions.
        try:
            _log.debug("About to wait for etcd update %s", last_etcd_index + 1)
            response = client.read("/calico/",
                                   wait=True,
                                   waitIndex=last_etcd_index + 1,
                                   recursive=True,
                                   timeout=0)
            _log.debug("etcd response: %r", response)
        except EtcdException:
            _log.exception("Failed to read from etcd. wait_index=%s",
                           last_etcd_index)
            raise
        last_etcd_index = response.etcd_index
        if response.value == last_value and response.key == last_key:
            _log.debug("Skipping duplicate update")
            continue
        last_key = response.key
        last_value = response.value

        profile_id, profile = parse_if_profile(response)
        if profile_id:
            _log.info("Scheduling profile update %s", profile_id)
            # TODO: we fire-and-forget this message, should make sure we resync on failure
            update_sequencer.on_profile_change(profile_id, profile,
                                               async=True)
            continue
        endpoint_id, endpoint = parse_if_endpoint(response)
        if endpoint_id:
            _log.info("Scheduling endpoint update %s", endpoint_id)
            update_sequencer.on_endpoint_change(endpoint_id, endpoint,
                                                async=True)
            continue


# Intern JSON keys as we load them to reduce occupancy.
def intern_dict(d):
    return dict((intern(str(k)), v) for k,v in d.iteritems())
json_decoder = json.JSONDecoder(object_hook=intern_dict)


def parse_if_endpoint(etcd_node):
    m = ENDPOINT_RE.match(etcd_node.key)
    if m:
        # Got an endpoint.
        endpoint_id = m.group("endpoint_id")
        if etcd_node.action == "delete":
            endpoint = None
        else:
            hostname = m.group("hostname")
            endpoint = json_decoder.decode(etcd_node.value)
            endpoint["host"] = hostname
        return endpoint_id, endpoint
    return None, None


def parse_if_profile(etcd_node):
    m = PROFILE_RE.match(etcd_node.key)
    if m:
        # Got a profile.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            profile = None
        else:
            profile = json_decoder.decode(etcd_node.value)
        return profile_id, profile
    return None, None
