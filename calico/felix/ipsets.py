# -*- coding: utf-8 -*-
# Copyright (c) 2015 Metaswitch Networks
# All Rights Reserved.
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
felix.ipsets
~~~~~~~~~~~~

IP sets management functions.
"""

import logging
from subprocess import CalledProcessError
from calico.felix.actor import Actor, actor_event
from gevent import subprocess
import re

_log = logging.getLogger(__name__)


class IpsetPool(Actor):
    @actor_event
    def allocate_ipset(self, id_tag):
        """
        Allocate an ipset from the pool.  If an existing ipset exists with
        the name provided, will return that set with its members as-loaded
        from the kernel.  Otherwise, queues a flush on the returned ipset.

        Guarantees that the ipset returned already exists in the kernel by the
        time it is returned.

        :param id_tag: Name to associate with this ipset.  Used to retrieve the
               same underlying ipset across process invocations.  Note: this
               may not be the name of the ipset itself.
        :return: an IpsetUpdater.
        """

        # TODO: replace this simple version with an actual pool!
        ipset = IpsetUpdater(tag_to_ipset_name(id_tag), "hash:ip").start()
        ipset.replace_members(set())
        return ipset

    @actor_event
    def return_ipset(self, ipset):
        """
        Returns an ipset ot the pool so that it may be reused.
        :param IpsetUpdater ipset:
        """
        pass


def tag_to_ipset_name(tag_name):
    assert re.match(r'^\w+$', tag_name), "Tags must be alphanumeric for now"
    return "calico-tag-" + tag_name


class IpsetUpdater(Actor):

    def __init__(self, name, set_type):
        super(IpsetUpdater, self).__init__()

        self.name = name
        self.set_type = set_type
        self.members = set()
        """Database state"""

        self.programmed_members = None
        """
        State loaded from ipset command.  None if we haven't loaded
        yet or the set doesn't exist.
        """

        self._load_from_ipset(async=True)

    @actor_event
    def replace_members(self, members):
        _log.info("Replacing members of ipset %s", self.name)
        assert isinstance(members, set), "Expected members to be a set"
        self.members = members
        self._sync_to_ipset()

    @actor_event
    def add_member(self, member):
        _log.info("Adding member %s to ipset %s", member, self.name)
        self.members.add(member)
        self._sync_to_ipset()

    @actor_event
    def remove_member(self, member):
        _log.info("Removing member %s from ipset %s", member, self.name)
        try:
            self.members.remove(member)
        except KeyError:
            _log.info("%s was not in ipset %s", member, self.name)
        else:
            self._sync_to_ipset()

    @actor_event
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

    def _sync_to_ipset(self):
        if self.programmed_members is None:
            # We're only called after _load_from_ipset() so we know that the
            # ipset doesn't exist.
            subprocess.check_output(
                ["ipset", "create", self.name, self.set_type])
            self.programmed_members = set()
        _log.debug("Programmed members: %s", self.programmed_members)
        _log.debug("Desired members: %s", self.members)
        members_to_add = self.members - self.programmed_members
        _log.debug("Adding members: %s", members_to_add)
        for member in members_to_add:
            subprocess.check_output(["ipset", "add", self.name, member])
            self.programmed_members.add(member)
        members_to_remove = self.programmed_members - self.members
        _log.debug("Removing members: %s", members_to_remove)
        for member in members_to_remove:
            subprocess.check_output(["ipset", "del", self.name, member])
            self.programmed_members.remove(member)
        assert self.programmed_members == self.members


