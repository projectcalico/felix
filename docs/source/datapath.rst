.. # Copyright (c) Metaswitch Networks 2015. All rights reserved.
   #
   #    Licensed under the Apache License, Version 2.0 (the "License"); you may
   #    not use this file except in compliance with the License. You may obtain
   #    a copy of the License at
   #
   #         http://www.apache.org/licenses/LICENSE-2.0
   #
   #    Unless required by applicable law or agreed to in writing, software
   #    distributed under the License is distributed on an "AS IS" BASIS,
   #    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   #    implied. See the License for the specific language governing
   #    permissions and limitations under the License.

The Calico Data Path: IP Routing and iptables
=============================================

One of Calico’s key features is that packets flow between workloads in a data
center, or between a workload and the Internet, all without additional
encapsulation.

In the Calico approach, IP packets to or from a workload are routed and
firewalled by the Linux routing table and iptables infrastructure on the
workload’s host.  For a workload that is sending packets, Calico ensures that
the host is always returned as the next hop MAC address regardless of whatever
routing the workload itself might configure. For packets addressed to a
workload, the last IP hop is that from the destination workload’s host to the
workload itself.

.. figure:: _static/calico-datapath.png
   :alt: Calico IP hops between two workloads

The first hop
-------------

DHCP
~~~~

When a VM boots, it sends a DHCPDICSOVER over the tap interface.  Each
compute host runs a DHCP agent for each Neutron network that the VMs on that
compute host are attached to, which handles IP address distribution for that
network to the relevant VMs.  When the DHCP server distributes IP address(es)
to a VM, it also tells the VM to use the gateway IP address(es) of the relevant
Neutron network as its default gateway.

ARP
~~~

Felix (a Calico agent) enables Proxy ARP on all TAP (or veth, etc.) interfaces
on each compute host.  Together with the gateway address, Proxy ARP ensures
that the first IP hop for traffic sent from a workload is always to that
workload's host.

When a workload needs to send an IP packet within its Neutron network, it ARPs
to the destination IP address, and Proxy ARP returns the MAC address of the TAP
interface (which is always 00:61:fe:ed:ca:fe to prevent ARP poisoning if the
workload is migrated).

When a workload needs to send an IP packet outside its network, it instead ARPs
the gateway IP, and thereby still sends the packet to its host.

Note that no Proxy ARP is required on the data center fabric itself - once the
packet has reached the host, normal IP routing takes over.

Inter-host routing
------------------

Suppose that IPv4 addresses for the workloads are allocated from a
datacenter-private subnet of 10.65/16, and that the hosts have IP addresses
from 172.18.203/24.  If you look at the routing table on a host you will see
something like this:

.. code::

 ubuntu@calico-ci02:~$ route -n
 Kernel IP routing table
 Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
 0.0.0.0         172.18.203.1    0.0.0.0         UG    0      0        0 eth0
 10.65.0.0       0.0.0.0         255.255.0.0     U     0      0        0 ns-db03ab89-b4
 10.65.0.21      172.18.203.126  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.22      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.23      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.24      0.0.0.0         255.255.255.255 UH    0      0        0 tapa429fb36-04
 172.18.203.0    0.0.0.0         255.255.255.0   U     0      0        0 eth0

There is one workload on this host with IP address 10.65.0.24, and accessible
from the host via a TAP (or veth, etc.) interface named tapa429fb36-04.  Hence
there is a direct route for 10.65.0.24, through tapa429fb36-04.  Other
workloads, with the .21, .22 and .23 addresses, are hosted on two other hosts
(172.18.203.126 and .129), so the routes for those workload addresses are via
those hosts.

The direct routes are set up by a Calico agent named Felix, when it is asked to
provision connectivity for a particular workload.  A BGP client (such as BIRD)
then notices those and distributes them – perhaps via a route reflector – to
BGP clients running on other hosts, and hence the indirect routes appear also.

Bookended security
------------------

The routing above in principle allows any workload in a data center to
communicate with any other – but in general an operator will want to restrict
that; for example, so as to isolate customer A’s workloads from those of
customer B.  Therefore Calico also programs iptables on each host, to specify
the IP addresses (and optionally ports etc.) that each workload is allowed to
send to or receive from.  This programming is ‘bookended’ in that the traffic
between workloads X and Y will be firewalled by both X’s host and Y’s host –
this helps to keep unwanted traffic off the data center’s core network, and as
a secondary defence in case it is possible for a rogue workload to compromise
its local host.

Is that all?
------------

As far as the static data path is concerned, yes.  It’s just a combination of
responding to workload ARP requests with the host MAC, IP routing and iptables.
There’s a great deal more to Calico in terms of how the required routing and
security information is managed, and for handling dynamic things such as
workload migration – but the basic data path really is that simple.
