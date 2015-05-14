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
calico.datamodel
~~~~~~~~~~~~~~~~

Shared etcd data-model definitions for version 1 of the data model.

This file is versioned.  The idea is that only back-compatible changes
should be made to this file and non-back-compatible changes should be
made in a new copy of the file with revved version suffix.  That allows
us to maintain multiple copies of the data model in parallel during
migrations.
"""
from collections import namedtuple
import logging
import re

_log = logging.getLogger(__name__)

# All Calico data is stored under this path.
ROOT_DIR = "/calico"

# Data that flows from orchestrator to felix is stored under a versioned
# sub-tree.
VERSION_DIR = ROOT_DIR + "/v1"
# Global ready flag.  Stores 'true' or 'false'.
READY_KEY = VERSION_DIR + "/Ready"
# Global config (directory).
CONFIG_DIR = VERSION_DIR + '/config'
HOST_DIR = VERSION_DIR + '/host'
POLICY_DIR = VERSION_DIR + '/policy'
PROFILE_DIR = POLICY_DIR + "/profile"

# Key used for leader election by Neutron mechanism drivers.
NEUTRON_ELECTION_KEY = VERSION_DIR + '/neutron_election'

# Regex to match profile rules, capturing the profile ID in capture group
# "profile_id".
RULES_KEY_RE = re.compile(
    r'^' + PROFILE_DIR + r'/(?P<profile_id>[^/]+)/rules')
# Regex to match profile tags, capturing the profile ID in capture group
# "profile_id".
TAGS_KEY_RE = re.compile(
    r'^' + PROFILE_DIR + r'/(?P<profile_id>[^/]+)/tags')

# Regex to match profile refcounts, capturing the profile ID in capture group
# "profile_id".
PROFILE_REFCOUNT_RE = re.compile(
    r'^' + PROFILE_DIR + r'/(?P<profile_id>[^/]+)/refcount')

# Regex to match profiles.
PROFILE_KEY_RE = re.compile(
    r'^' + PROFILE_DIR + r'/(?P<profile_id>[^/]+)$')

# Regex to match endpoints.
ENDPOINT_KEY_RE = re.compile(
    r'^' + HOST_DIR +
    r'/(?P<hostname>[^/]+)/'
    r'workload/'
    r'(?P<orchestrator>[^/]+)/'
    r'(?P<workload_id>[^/]+)/'
    r'endpoint/(?P<endpoint_id>[^/]+)$')

# Regex to match workloads or the endpoint directory below it.
WORKLOAD_KEY_RE = re.compile(
    r'^' + HOST_DIR +
    r'/(?P<hostname>[^/]+)/'
    r'workload/'
    r'(?P<orchestrator>[^/]+)/'
    r'(?P<workload_id>[^/]+)'
    r'(/endpoint){0,1}$')

# Regex to match orchestrators.
ORCHESTRATOR_KEY_RE = re.compile(
    r'^' + HOST_DIR +
    r'/(?P<hostname>[^/]+)/'
    r'workload/'
    r'(?P<orchestrator>[^/]+)$')

# Regex to match either a host or the workload directory below it
HOST_KEY_RE = re.compile(
    r'^' + HOST_DIR +
    r'/(?P<hostname>[^/]+)'
    r'(/workload){0,1}$')

# Types of object which has been deleted; see delete_action for more. If a single object is affected, then the type is associated with a list of objects Each action is returned with a list indicating what objects have been affected,

DELETED_NONE = "nothing"
DELETED_ALL = "all"
DELETED_TAGS = "tags"
DELETED_RULES = "rules"
DELETED_PROFILE = "profile"
DELETED_ENDPOINT = "endpoint"
DELETED_WORKLOAD = "workload"
DELETED_ORCHESTRATOR = "orchestrator"
DELETED_HOST = "host"

def delete_action(path):
    """
    Given a key path that has been deleted, return what has been removed.
    :param path: path which has been deleted
    :returns: a dictionary indicating what is gone.

    The dictionary contains a key "type" whose value is one of the DELETED_*
    fields. Other keys in the dict are specified as follows.

    DELETED_NONE         : []
    DELETED_ALL          : []
    DELETED_RULES        : [profile]
    DELETED_TAGS         : [profile]
    DELETED_PROFILE      : [profile]
    DELETED_ENDPOINT     : [host, orchestrator, workload, endpoint]
    DELETED_WORKLOAD     : [host, orchestrator, workload]
    DELETED_ORCHESTRATOR : [host, orchestrator]
    DELETED_HOST         : [host]
    """
    path = path.rstrip('/')

    if path in (ROOT_DIR, VERSION_DIR, HOST_DIR, POLICY_DIR,
                PROFILE_DIR, READY_KEY):
        # We have lost so much information that we should resync completely.
        return {"type": DELETED_ALL}

    m = RULES_KEY_RE.match(path)
    if m:
        return {"type": DELETED_RULES,
                "profile": m.group("profile_id")}

    m = TAGS_KEY_RE.match(path)
    if m:
        return {"type": DELETED_TAGS,
                "profile": m.group("profile_id")}

    m = PROFILE_KEY_RE.match(path)
    if m:
        return {"type": DELETED_PROFILE,
                "profile": m.group("profile_id")}

    m = ENDPOINT_KEY_RE.match(path)
    if m:
        return {"type": DELETED_ENDPOINT,
                "host": m.group("hostname"),
                "orchestrator": m.group("orchestrator"),
                "workload": m.group("workload_id"),
                "endpoint": m.group("endpoint_id")}

    m = WORKLOAD_KEY_RE.match(path)
    if m:
        return {"type": DELETED_WORKLOAD,
                "host": m.group("hostname"),
                "orchestrator": m.group("orchestrator"),
                "workload": m.group("workload_id")}

    m = ORCHESTRATOR_KEY_RE.match(path)
    if m:
        return {"type": DELETED_ORCHESTRATOR,
                "host": m.group("hostname"),
                "orchestrator": m.group("orchestrator")}

    m = HOST_KEY_RE.match(path)
    if m:
        return {"type": DELETED_HOST,
                "host": m.group("hostname")}

    # Some field we do not care about.
    return {"type": DELETED_NONE}


def dir_for_host(hostname):
    return HOST_DIR+ "/%s" % hostname


def dir_for_per_host_config(hostname):
    return dir_for_host(hostname) + "/config"


def key_for_endpoint(host, orchestrator, workload_id, endpoint_id):
    return (HOST_DIR + "/%s/workload/%s/%s/endpoint/%s" %
            (host, orchestrator, workload_id, endpoint_id))


def key_for_profile(profile_id):
    return PROFILE_DIR + "/" + profile_id


def key_for_profile_rules(profile_id):
    return PROFILE_DIR + "/%s/rules" % profile_id


def key_for_profile_tags(profile_id):
    return PROFILE_DIR + "/%s/tags" % profile_id

def key_for_config(config_name):
    return CONFIG_DIR + "/%s" % config_name

class EndpointInfo(namedtuple("EndpointInfo", ["host", "orchestrator",
                                               "workload", "endpoint"])):
    def __str__(self):
        return self.__class__.__name__ + ("<%s/%s/%s/%s>" % self)
