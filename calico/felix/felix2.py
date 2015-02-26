# Copyright (c) Metaswitch Networks 2015. All rights reserved.
from collections import defaultdict
import functools
from subprocess import CalledProcessError

from gevent import monkey

monkey.patch_all()

import logging
import gevent
from gevent.queue import Queue
from gevent.event import Event, AsyncResult
from gevent import subprocess
import etcd
import json

_log = logging.getLogger(__name__)


update_queue = Queue()

# Convention: always end with "/" to avoid matching /foobar/... when we mean to match /foo/...
ROOT_PFX = "/"
CALICO_PFX = ROOT_PFX + "calico/"
NETWORK_PFX = CALICO_PFX + "network/"
PROFILE_PFX = NETWORK_PFX + "profiles/"
ENDPOINT_PFX = NETWORK_PFX + "endpoints/"


def actor_event(fn):
    fn.actor_event = True
    return fn


def _make_queue_fn(event_fn):
    def queue_fn(self, *args, **kwargs):
        future = AsyncResult()
        self._event_queue.put((future, event_fn, args, kwargs))
        return future
    return queue_fn


class ActorMetaclass(type):
    def __new__(mcs, name, bases, attrs):

        for key, value in attrs.iteritems():
            if hasattr(value, "actor_event"):
                # We've got an event, replace with a function that queues the input.
                attrs[key] = _make_queue_fn(value)

        return super(ActorMetaclass, mcs).__new__(mcs, name, bases, attrs)


class Actor(object):
    __metaclass__ = ActorMetaclass

    def __init__(self):
        self._event_queue = Queue()
        gevent.spawn(self._loop)

    def _loop(self):
        while True:
            future, fn, args, kwargs = self._event_queue.get()
            assert isinstance(future, AsyncResult)
            try:
                result = fn(self, *args, **kwargs)
            except BaseException as e:
                _log.exception("Exception on loop")
                future.set_exception(e)
            else:
                future.set(result)


class ObservableActor(Actor):

    def __init__(self):
        super(ObservableActor, self).__init__()
        self.referrers = set()
        
    @actor_event
    def add_referrer(self, referrer):
        _log.debug("Adding referrer %s", referrer)
        was_in_use = self.in_use
        self.referrers.add(referrer)
        if not was_in_use:
            self._on_has_referrers()

    @actor_event
    def remove_referrer(self, referrer):
        self.referrers.remove(referrer)
        if not self.in_use:
            self._on_has_no_referrers()

    def _on_has_referrers(self):
        pass

    def _on_has_no_referrers(self):
        pass

    @property
    def in_use(self):
        return bool(self.referrers)


class RulesActor(ObservableActor):

    def __init__(self):
        super(RulesActor, self).__init__()
        self.profile_id = None
        self.rules = None
        self.current_state = None
        self.present_in_iptables = None
        self.referrers = set()

    @actor_event
    def on_profile_update(self, profile):
        self.rules = profile["rules"]
        if self.profile_id is None:
            # Very first update, stash the profile ID and sync our state from iptables.
            self.profile_id = profile["id"]
            self._load_rules_from_iptables()  # One-time load
        if self.in_use:
            # Someone is using this rule set, update it.
            self._sync_rules_to_iptables()

    def _on_has_referrers(self):
        self._sync_rules_to_iptables()

    def _load_rules_from_iptables(self):
        pass

    def _sync_rules_to_iptables(self):
        pass


class IpsetActor(ObservableActor):

    def __init__(self, name, set_type=None, initial_members=None):
        super(IpsetActor, self).__init__()

        self.name = name
        self.set_type = set_type or "hash:net,port"
        self.members = set()
        """Database state"""

        self.programmed_members = None
        """
        State loaded from ipset command.  None if we haven't loaded yet or the set doesn't
        exist.
        """

        self._load_from_ipset()
        if initial_members:
            self.update(initial_members)

    @actor_event
    def update(self, members):
        assert isinstance(members, set)
        self.members = members
        if self.in_use:
            self._sync_to_ipset()

    @actor_event
    def add_member(self, member):
        self.members.add(member)
        if self.in_use:
            self._sync_to_ipset()

    @actor_event
    def remove_member(self, member):
        self.members.remove(member)
        if self.in_use:
            self._sync_to_ipset()

    def _load_from_ipset(self):
        try:
            output = subprocess.check_output(["ipset", "list", self.name])
        except CalledProcessError as cpe:
            if cpe.returncode == 1:
                # ipset doesn't exist.  TODO: better check?
                self.programmed_members = None
            else:
                raise
        else:
            # Output ends with:
            # Members:
            # <one member per line>
            lines = output.splitlines()
            self.programmed_members = set(lines[lines.index("Members:") + 1:])

    def _on_has_referrers(self):
        _log.debug("ipset now has referrers, syncing")
        self._sync_to_ipset()

    def _sync_to_ipset(self):
        if self.programmed_members is None:
            subprocess.check_output(["ipset", "create", self.name, self.set_type])
            self.programmed_members = set()
        _log.debug("Programmed members: %s", self.programmed_members)
        _log.debug("Desired members: %s", self.members)
        members_to_add = self.members - self.programmed_members
        _log.debug("Adding members: %s", members_to_add)
        for member in members_to_add:
            subprocess.check_output(["ipset", "add", self.name, member])
        members_to_remove = self.programmed_members - self.members
        _log.debug("Removing members: %s", members_to_remove)
        for member in members_to_remove:
            subprocess.check_output(["ipset", "del", self.name, member])
        self.programmed_members = self.members



profile_actors = defaultdict(RulesActor)
""":type: dict of [str, ProfileFsm]"""


profiles_by_id = {}
endpoints_by_id = {}
endpoints_by_tag = defaultdict(set)


def monitor_etcd():
    client = etcd.Client()

    # Load initial dump from etcd.  First just get all the endpoints and profiles by id.
    initial_dump = client.read("/calico/", recursive=True)
    for child in initial_dump.children:
        if child.key.startswith(PROFILE_PFX):
            profile = json.loads(child.value)
            profiles_by_id[profile["id"]] = profile
        elif child.key.startswith(ENDPOINT_PFX):
            endpoint = json.loads(child.value)
            endpoints_by_id[endpoint["id"]] = endpoint
        else:
            _log.warn("Ignoring unknown key %s", child.key)

    # Then build our indexes.
    for endpoint_id, endpoint in endpoints_by_id.iteritems():
        profile_id = endpoint["profile"]
        tags = profiles_by_id[profile_id].tags
        for tag in tags:
            endpoints_by_tag[tag].add(endpoint_id)



def on_profile_update(profile):
    """
    :type profile: dict
    """
    profile_id = profile["id"]
    profile_actor = get_profile_actor(profile_id)
    profile_actor.on_profile_update(profile)


def on_endpoint_update(endpoint):
    pass


def main():
    pass
