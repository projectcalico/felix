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
from types import StringTypes
from etcd import EtcdException
import etcd
import re
from urllib3.exceptions import ReadTimeoutError

_log = logging.getLogger(__name__)


# etcd path regexes
RULES_RE = re.compile(
    r'^/calico/policy/profile/(?P<profile_id>[^/]+)/rules')
TAGS_RE = re.compile(
    r'^/calico/policy/profile/(?P<profile_id>[^/]+)/tags')
ENDPOINT_RE = re.compile(
    r'^/calico/host/(?P<hostname>[^/]+)/.+/endpoint/(?P<endpoint_id>[^/]+)')


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
    client = etcd.Client('localhost', 4001)

    # Load initial dump from etcd.  First just get all the endpoints and
    # profiles by id.  The response contains a generation ID allowing us
    # to then start polling for updates without missing any.
    initial_dump = client.read("/calico/", recursive=True)
    rules_by_id = {}
    tags_by_id = {}
    endpoints_by_id = {}
    for child in initial_dump.children:
        profile_id, rules = parse_if_rules(child)
        if profile_id:
            rules_by_id[profile_id] = rules
            continue
        profile_id, tags = parse_if_tags(child)
        if profile_id:
            tags_by_id[profile_id] = tags
            continue
        endpoint_id, endpoint = parse_if_endpoint(child)
        if endpoint_id and endpoint:
            endpoints_by_id[endpoint_id] = endpoint
            continue

    # Actually apply the snapshot.  The UpdateSequencer will apply deltas as
    # appropriate.  Grab the future in case it raises an error.
    f_apply_snap = update_sequencer.apply_snapshot(rules_by_id,
                                                   tags_by_id,
                                                   endpoints_by_id,
                                                   async=True)
    # Now owned by the update sequencer...
    del rules_by_id
    del tags_by_id
    del endpoints_by_id

    last_etcd_index = initial_dump.etcd_index
    del initial_dump

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
        except ReadTimeoutError:
            _log.warning("Read from etcd timed out, retrying.")
            continue
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

        # TODO: we fire-and-forget these messages...
        # TODO: regex parsing getting messy.
        profile_id, rules = parse_if_rules(response)
        if profile_id:
            _log.info("Scheduling profile update %s", profile_id)
            update_sequencer.on_rules_update(profile_id, rules, async=True)
            continue
        profile_id, tags = parse_if_tags(response)
        if profile_id:
            _log.info("Scheduling profile update %s", profile_id)
            update_sequencer.on_tags_update(profile_id, tags, async=True)
            continue
        endpoint_id, endpoint = parse_if_endpoint(response)
        if endpoint_id:
            _log.info("Scheduling endpoint update %s", endpoint_id)
            update_sequencer.on_endpoint_update(endpoint_id, endpoint,
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
            try:
                validate_endpoint(endpoint)
            except ValidationFailed as e:
                _log.warning("Validation failed for endpoint %s, treating as "
                             "missing: %s", endpoint_id, e.message)
                return endpoint_id, None
            endpoint["host"] = hostname
            endpoint["id"] = endpoint_id
        return endpoint_id, endpoint
    return None, None


def validate_endpoint(endpoint):
    issues = []

    if "state" not in endpoint:
        issues.append("Missing 'state' field.")
    elif endpoint["state"] not in ("active", "inactive"):
        issues.append("Expected 'state' to be one of active/inactive.")

    for field in ["name", "mac", "profile_id"]:
        if field not in endpoint:
            issues.append("Missing '%s' field." % field)
        elif not isinstance(endpoint[field], StringTypes):
            issues.append("Expected '%s' to be a string; got %r." %
                          (field, endpoint[field]))

    if issues:
        raise ValidationFailed(", ".join(issues))


class ValidationFailed(Exception):
    pass


def parse_if_rules(etcd_node):
    m = RULES_RE.match(etcd_node.key)
    if m:
        # Got some rules.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            rules = None
        else:
            rules = json_decoder.decode(etcd_node.value)
            rules["id"] = profile_id
        return profile_id, rules
    return None, None


def parse_if_tags(etcd_node):
    m = TAGS_RE.match(etcd_node.key)
    if m:
        # Got some tags.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            tags = None
        else:
            tags = json_decoder.decode(etcd_node.value)
        return profile_id, tags
    return None, None
