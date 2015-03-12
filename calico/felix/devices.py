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
felix.devices
~~~~~~~~~~~~

Utility functions for managing devices in Felix.
"""
import logging
import collections
from calico.felix.actor import Actor, actor_event
import gevent
from gevent import subprocess
import os

from calico import common
from calico.felix import futils

# Logger
import re

_log = logging.getLogger(__name__)


def interface_exists(interface):
    """
    Returns True if interface device exists.
    """
    return os.path.exists("/sys/class/net/" + interface)


def list_interface_ips(type, interface):
    """
    List IP addresses for which there are routes to a given interface.
    Returns a set with all addresses for which there is a route to the device.
    """
    ips = set()

    if type == futils.IPV4:
        data = futils.check_call(
            ["ip", "route", "list", "dev", interface]).stdout
    else:
        data = futils.check_call(
            ["ip", "-6", "route", "list", "dev", interface]).stdout

    lines = data.split("\n")

    _log.debug("Existing routes to %s : %s" % (interface, ",".join(lines)))

    for line in lines:
        #*********************************************************************#
        #* Example of the lines we care about is (having specified the       *#
        #* device above) :                                                   *#
        #* 10.11.2.66 proto static scope link                                *#
        #*********************************************************************#
        words = line.split()

        if len(words) > 1:
            ip = words[0]
            if common.validate_ip_addr(ip, None):
                # Looks like an IP address. Note that we here are ignoring
                # routes to networks configured when the interface is created.
                ips.add(words[0])

    _log.debug("Found existing IP addresses : %s", ips)

    return ips


def configure_interface(interface):
    """
    Configure the various proc file system parameters for the interface.

    Specifically, allow packets from controlled interfaces to be directed to
    localhost, and enable proxy ARP.
    """
    with open('/proc/sys/net/ipv4/conf/%s/route_localnet' % interface, 'wb') as f:
        f.write('1')

    with open("/proc/sys/net/ipv4/conf/%s/proxy_arp" % interface, 'wb') as f:
        f.write('1')

    with open("/proc/sys/net/ipv4/neigh/%s/proxy_delay" % interface, 'wb') as f:
        f.write('0')


def add_route(type, ip, interface, mac):
    """
    Add a route to a given interface (including arp config).
    Errors lead to exceptions that are not handled here.

    Note that we use "ip route replace", since that overrides any imported
    routes to the same IP, which might exist in the middle of a migration.
    """
    if type == futils.IPV4:
        futils.check_call(['arp', '-s', ip, mac, '-i', interface])
        futils.check_call(["ip", "route", "replace", ip, "dev", interface])
    else:
        futils.check_call(["ip", "-6", "route", "replace", ip, "dev", interface])


def del_route(type, ip, interface):
    """
    Delete a route to a given interface (including arp config).
    Errors lead to exceptions that are not handled here.
    """
    if type == futils.IPV4:
        futils.check_call(['arp', '-d', ip, '-i', interface])
        futils.check_call(["ip", "route", "del", ip, "dev", interface])
    else:
        futils.check_call(["ip", "-6", "route", "del", ip, "dev", interface])


def interface_up(if_name):
    """
    Checks whether a given interface is up.
    """
    with open('/sys/class/net/%s/operstate' % if_name, 'r') as f:
        state = f.read()

    return 'up' in state


InterfaceState = collections.namedtuple("Interface",
                                        ["name", "iface_id", "up"])


class InterfaceWatcher(Actor):
    def __init__(self, update_sequencer):
        super(InterfaceWatcher, self).__init__()
        self.update_sequencer = update_sequencer
        self.interfaces = {}

    @actor_event
    def poll_interfaces(self):
        """
        Issues a single poll of the interfaces and sends updates to the
        update sequencer.
        """
        # TODO: use netlink socket to monitor rather than poll?
        # FIXME: this doesn't detect if an interface quickly flaps down/up
        # Use "ip link" to get the list of interfaces and their kernel IDs.
        # The kernel ID should change if an interface with a particular ID
        # is removed and then added back in-between polls.
        output = subprocess.check_output(["ip", "link"])
        # Lines we care about look like this:
        # 1234: iface_name: <UP,SOME_FLAG,LOWER_UP> ...
        # Regex extracts "1234", "iface_name" and "UP,SOME_FLAG,LOWER_UP".
        seen_interfaces = set()
        for num, name, attrs in re.findall(r"^(\d+): ([^:]+): <([^>]+)>",
                                           output, flags=re.MULTILINE):
            seen_interfaces.add(name)
            is_up = "UP" in attrs.split(",")
            old_state = self.interfaces.get(name)
            new_state = InterfaceState(name=name, iface_id=int(num), up=is_up)
            if old_state != new_state:
                _log.info("Interface %s changed state: %s", name, new_state)
                self.interfaces[name] = new_state
                if old_state and old_state.iface_id != new_state.iface_id:
                    # Interface ID has changed, indicates the interface
                    # was deleted and then re-added.
                    _log.debug("Interface ID changed for %s. simulating "
                               "remove then add.", name)
                    self.update_sequencer.on_interface_update(name, None)
                self.update_sequencer.on_interface_update(name, new_state,
                                                          async=True)
        previous_interfaces = set(self.interfaces.keys())
        for removed_interface in previous_interfaces - seen_interfaces:
            _log.info("Interface %s went away.", removed_interface)
            del self.interfaces[removed_interface]
            self.update_sequencer.on_interface_update(removed_interface,
                                                      None)
            
    @actor_event
    def watch_interfaces(self):
        """
        Watches linux interfaces come and go and fires events
        into the update sequencer.

        :returns: Never returns.
        """
        while True:
            self.poll_interfaces(async=False)  # Skips queue
            gevent.sleep(0.5)