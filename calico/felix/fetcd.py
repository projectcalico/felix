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
import itertools
import json
import logging
from calico.felix.futils import logging_exceptions
from types import StringTypes
from etcd import EtcdException
import etcd
import re
from urllib3.exceptions import ReadTimeoutError
from netaddr import IPAddress, AddrFormatError

from calico import common

_log = logging.getLogger(__name__)


# etcd path regexes
RULES_RE = re.compile(
    r'^/calico/policy/profile/(?P<profile_id>[^/]+)/rules')
TAGS_RE = re.compile(
    r'^/calico/policy/profile/(?P<profile_id>[^/]+)/tags')
ENDPOINT_RE = re.compile(
    r'^/calico/host/(?P<hostname>[^/]+)/.+/endpoint/(?P<endpoint_id>[^/]+)')


class ValidationFailed(Exception):
    pass


@logging_exceptions
def watch_etcd(config, update_splitter):
    """
    Loads the snapshot from etcd and then monitors etcd for changes.
    Posts events to the UpdateSplitter.

    Intended to be used as a greenlet.  Intended to be restarted if
    it raises an exception.

    :returns: Does not return.
    :raises EtcdException: if a read from etcd fails and we may fall out of
            sync.
    """
    client = etcd.Client('localhost', config.ETCD_PORT)

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
        endpoint_id, endpoint = parse_if_endpoint(config, child)
        if endpoint_id and endpoint:
            endpoints_by_id[endpoint_id] = endpoint
            continue

    # Actually apply the snapshot, grabbing the future in case it raises an error.
    f_apply_snap = update_splitter.apply_snapshot(rules_by_id,
                                                  tags_by_id,
                                                  endpoints_by_id)

    # These read only objects are no longer required, so tidy them up.
    del rules_by_id
    del tags_by_id
    del endpoints_by_id

    # On first call, the etcd_index seems to be the high-water mark for the
    # data returned whereas the modified index just tells us when the key
    # was modified.
    _log.info("Initial etcd index: %s; modifiedIndex: %s",
              initial_dump.etcd_index, initial_dump.modifiedIndex)
    last_etcd_index = initial_dump.etcd_index
    del initial_dump
    while True:
        if f_apply_snap and f_apply_snap.ready():
            # Snapshot application finished, check for exceptions.
            _log.info("Snapshot application returned, checking for errors.")
            f_apply_snap.get_nowait()
            f_apply_snap = None

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
            # TODO: We are timing out after 60 seconds, perhaps because we
            # should be using "read_timeout" not "timeout". However, a
            # timeout of 0 is probably wrong if that does not reestablish
            # connections periodically. Needs a bit more thought.
            continue
        except EtcdException:
            _log.exception("Failed to read from etcd. wait_index=%s",
                           last_etcd_index)
            raise
        # Defensive, the etcd_index returned on subsequent requests is the one
        # that we waited on and the modifiedIndex is the index at which the
        # key's value was changed. Just in case there's a corner case where
        # we get an old modifiedIndex, make sure we always increase the index.
        last_etcd_index = max(response.modifiedIndex, last_etcd_index + 1)

        # TODO: regex parsing getting messy.
        profile_id, rules = parse_if_rules(response)
        if profile_id:
            _log.info("Scheduling profile update %s", profile_id)
            update_splitter.on_rules_update(profile_id, rules)
            continue
        profile_id, tags = parse_if_tags(response)
        if profile_id:
            _log.info("Scheduling profile update %s", profile_id)
            update_splitter.on_tags_update(profile_id, tags)
            continue
        endpoint_id, endpoint = parse_if_endpoint(config, response)
        if endpoint_id:
            _log.info("Scheduling endpoint update %s", endpoint_id)
            update_splitter.on_endpoint_update(endpoint_id, endpoint)
            continue


# Intern JSON keys as we load them to reduce occupancy.
def intern_dict(d):
    return dict((intern(str(k)), v) for k,v in d.iteritems())
json_decoder = json.JSONDecoder(object_hook=intern_dict)


def parse_if_endpoint(config, etcd_node):
    m = ENDPOINT_RE.match(etcd_node.key)
    if m:
        # Got an endpoint.
        endpoint_id = m.group("endpoint_id")
        if etcd_node.action == "delete":
            endpoint = None
            _log.debug("Found deleted endpoint %s", endpoint_id)
        else:
            hostname = m.group("hostname")
            endpoint = json_decoder.decode(etcd_node.value)
            try:
                validate_endpoint(config, endpoint)
            except ValidationFailed as e:
                _log.warning("Validation failed for endpoint %s, treating as "
                             "missing: %s", endpoint_id, e.message)
                return endpoint_id, None
            endpoint["host"] = hostname
            endpoint["id"] = endpoint_id
            _log.debug("Found endpoint : %s", endpoint)
        return endpoint_id, endpoint
    return None, None


def validate_endpoint(config, endpoint):
    """
    Ensures that the supplied endpoint is valid. Once this routine has returned
    successfully, we know that all required fields are present and have valid values.

    :param config: configuration structure
    :param endpoint: endpoint dictionary as read from etcd
    :raises ValidationFailed
    """
    issues = []

    if not isinstance(endpoint, dict):
        raise ValidationFailed("Expected endpoint to be a dict.")

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

    if "name" in endpoint:
        if not endpoint["name"].startswith(config.IFACE_PREFIX):
            issues.append("Interface %r does not start with %r." %
                          (endpoint["name"], config.IFACE_PREFIX))

    for version in (4, 6):
        nets = "ipv%d_nets" % version
        if nets not in endpoint:
            issues.append("Missing network %s." % nets)
        else:
            for ip in endpoint.get(nets, []):
                if not common.validate_cidr(ip, version):
                    issues.append("IP address %r is not a valid IPv%d CIDR." %
                                  (ip, version))
                    break

        gw_key = "ipv%d_gateway" % version
        try:
            gw_str = endpoint[gw_key]
            if not common.validate_ip_addr(gw_str, version):
                issues.append("%s is not a valid IPv%d gateway address." %
                              (gw_key, version))
        except KeyError:
            pass

    if issues:
        raise ValidationFailed(" ".join(issues))


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
            try:
                validate_rules(rules)
            except ValidationFailed as e:
                _log.exception("Validation failed for profile %s rules : %s",
                             profile_id, rules)
                return profile_id, None

        _log.debug("Found rules for profile %s : %s", profile_id, rules)

        return profile_id, rules
    return None, None


def validate_rules(rules):
    """
    Ensures that the supplied rules are valid. Once this routine has returned
    successfully, we know that all required fields are present and have valid values.

    :param rules: rules list as read from etcd
    :raises ValidationFailed
    """
    issues = []

    if not isinstance(rules, dict):
        raise ValidationFailed("Expected rules to be a dict.")

    for key in ("inbound_rules", "outbound_rules"):
        if key not in rules:
            issues.append("No %s in rules." % key)
            continue

    #TODO: need to consider what further firewalling to add here.

    if issues:
        raise ValidationFailed(" ".join(issues))


def parse_if_tags(etcd_node):
    m = TAGS_RE.match(etcd_node.key)
    if m:
        # Got some tags.
        profile_id = m.group("profile_id")
        if etcd_node.action == "delete":
            tags = None
        else:
            tags = json_decoder.decode(etcd_node.value)
            try:
                validate_tags(tags)
            except ValidationFailed:
                _log.exception("Validation failed for profile %s tags : %s",
                               profile_id, tags)
                return profile_id, None

        _log.debug("Found tags for profile %s : %s", profile_id, tags)

        return profile_id, tags
    return None, None


def validate_tags(tags):
    """
    Ensures that the supplied tags are valid. Once this routine has returned
    successfully, we know that all required fields are present and have valid
    values.

    :param config: configuration structure
    :param tags: tag set as read from etcd
    :raises ValidationFailed
    """
    issues = []

    if not isinstance(tags, list):
        issues.append("Expected tags to be a list.")
    else:
        for tag in tags:
            if not isinstance(tag, StringTypes):
                issues.append("Expected tag '%s' to be a string." % tag)
                break

    if issues:
        raise ValidationFailed(" ".join(issues))

def load_config(host, port):
    """
    TODO: Add watching of the config.

    Load configuration detail for this host from etcd.
    :returns: a dictionary of key to paarameters
    :raises EtcdException: if a read from etcd fails and we may fall out of
            sync.
    """
    client = etcd.Client(port=port)

    config_dict = {}

    # Load initial dump from etcd.  First just get all the endpoints and
    # profiles by id.  The response contains a generation ID allowing us
    # to then start polling for updates without missing any.
    global_cfg = client.read("/calico/config/")
    host_cfg = client.read("/calico/host/%s/config/" % host)

    for child in itertools.chain(global_cfg.children, host_cfg.children):
        _log.info("Got config parameter : %s=%s", child.key, str(child.value))
        key = child.key.rsplit("/").pop()
        value = str(child.value)
        config_dict[key] = value

    return config_dict
