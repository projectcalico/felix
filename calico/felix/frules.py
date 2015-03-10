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
felix.frules
~~~~~~~~~~~~

Felix rule management, including iptables and ipsets.
"""
import logging
from subprocess import CalledProcessError

_log = logging.getLogger(__name__)


# Chain names
CHAIN_PREROUTING = "fx-PREROUTING"
CHAIN_INPUT = "fx-INPUT"
CHAIN_FORWARD = "fx-FORWARD"
CHAIN_TO_ENDPOINT = "fx-TO-ENDPOINT"
CHAIN_FROM_ENDPOINT = "fx-FROM-ENDPOINT"
CHAIN_TO_PREFIX = "fx-to-"
CHAIN_FROM_PREFIX = "fx-from-"
CHAIN_PROFILE_PREFIX = "fx-p-"


# Valid keys for a rule JSON dict.
KNOWN_RULE_KEYS = set([
    "action",
    "protocol",
    "src_net",
    "src_tag",
    "src_ports",
    "dst_net",
    "dst_tag",
    "dst_ports",
    "icmp_type",
])


def profile_to_chain_name(inbound_or_outbound, profile_id):
    return CHAIN_PROFILE_PREFIX + "%s-%s" % (profile_id,
                                             inbound_or_outbound[:1])


def install_global_rules(config, v4_updater, v6_updater):
    """
    Set up global iptables rules. These are rules that do not change with
    endpoint, and are expected never to change (such as the rules that send all
    traffic through the top level Felix chains).

    This method therefore :

    - ensures that all the required global tables are present;
    - applies any changes required.
    """

    # The interface matching string; for example, if interfaces start "tap"
    # then this string is "tap+".
    iface_match = config.IFACE_PREFIX + "+"

    # The IPV4 nat table first. This must have a felix-PREROUTING chain.
    nat_pr = []
    if config.METADATA_IP is not None:
        # Need to expose the metadata server on a link-local.
        #  DNAT tcp -- any any anywhere 169.254.169.254
        #              tcp dpt:http to:127.0.0.1:9697
        nat_pr.append("--append " + CHAIN_PREROUTING + " "
                      "--protocol tcp "
                      "--dport 80 "
                      "--destination 169.254.169.254/32 "
                      "--jump DNAT --to-destination %s:%s" %
                      (config.METADATA_IP, config.METADATA_PORT))
    v4_updater.apply_updates("nat", [CHAIN_PREROUTING], nat_pr)

    # Ensure we have a rule that forces us through the chain we just created.
    rule = "PREROUTING --jump %s" % CHAIN_PREROUTING
    try:
        # Try to atomically delete and reinsert the rule, if we fail, we
        # assume it wasn't present and insert it.
        pr = ["--delete %s" % rule,
              "--insert %s" % rule]
        v4_updater.apply_updates("nat", [], pr)
    except CalledProcessError:
        _log.info("Failed to detect pre-routing rule, will insert it.")
        pr = ["--insert %s" % rule]
        v4_updater.apply_updates("nat", [], pr)

    # Now the filter table. This needs to have calico-filter-FORWARD and
    # calico-filter-INPUT chains, which we must create before adding any
    # rules that send to them.
    for iptables_updater in [v4_updater, v6_updater]:
        # FIXME: This flushes the FROM/TO_ENDPOINT chains.
        req_chains = [CHAIN_FROM_ENDPOINT, CHAIN_TO_ENDPOINT, CHAIN_INPUT,
                      CHAIN_FORWARD]

        updates = []

        # Add rules to the global chains to direct to our own.
        # Force FORWARD traffic to go through our chain.
        # TODO: remove any old version of the rule
        updates.extend([
            "--insert FORWARD --jump %s" % CHAIN_FORWARD
        ])
        # Force INPUT traffic to go through our chain.
        updates.extend([
            "--insert INPUT --jump %s" % CHAIN_INPUT
        ])

        # Configure our chains.
        # The felix forward chain tests traffic to and from endpoints
        updates.extend([
            "--append %s --jump %s --in-interface %s" %
                (CHAIN_FORWARD, CHAIN_FROM_ENDPOINT, iface_match),
            "--append %s --jump %s --out-interface %s" %
                (CHAIN_FORWARD, CHAIN_TO_ENDPOINT, iface_match),
            "--append %s --jump ACCEPT --in-interface %s" %
                (CHAIN_FORWARD, iface_match),
            "--append %s --jump ACCEPT --out-interface %s" %
                (CHAIN_FORWARD, iface_match),
        ])

        # The felix INPUT chain tests traffic from endpoints
        updates.extend([
            "--append %s --jump %s --in-interface %s" %
                (CHAIN_INPUT, CHAIN_FROM_ENDPOINT, iface_match),
            "--append %s --jump ACCEPT --in-interface %s" %
                (CHAIN_INPUT, iface_match),
        ])

        iptables_updater.apply_updates("filter", req_chains, updates)

def update_chain(name, rule_list, v4_updater, iptable="filter", async=False):
    """
    Atomically creates/replaces the contents of the named iptables chain
    with the rules from rule_list.
    :param list[dict] rule_list: Ordered list of rule dicts.
    :return: AsyncResult from the IPTABLES_UPDATER.
    """
    # Delete all rules int he chain.  This is done atomically with the
    # appends below so the end result will be a chain with only the new rules
    # in it.
    fragments = ["--flush %s" % name]
    fragments += [rule_to_iptables_fragment(name, r, on_allow="RETURN")
                  for r in rule_list]
    # TODO: IPv6 support
    return v4_updater.apply_updates(iptable, [name], fragments,
                                             async=async)


def rules_to_chain_rewrite_lines(chain_name, rules, ip_version, tag_to_ipset,
                                 on_allow="ACCEPT", on_deny="DROP"):
    fragments = []
    for r in rules:
        fragments.append(rule_to_iptables_fragment(chain_name, r, ip_version,
                                                   tag_to_ipset,
                                                   on_allow=on_allow,
                                                   on_deny=on_deny))
    return fragments


def rule_to_iptables_fragment(chain_name, rule, ip_version, tag_to_ipset,
                              on_allow="ACCEPT", on_deny="DROP"):
    """
    Convert a rule dict to an iptables fragment suitable to use with
    iptables-restore.

    :param str chain_name: Name of the chain this rule belongs to (used in the
           --append)
    :param dict[str,str|list|int] rule: Rule dict.
    :param str on_allow: iptables action to use when the rule allows traffic.
           For example: "ACCEPT" or "RETURN".
    :param str on_deny: iptables action to use when the rule denies traffic.
           For example: "DROP".
    :return str: iptables --append fragment.
    """

    # Check we've not got any unknown fields.
    unknown_keys = set(rule.keys()) - KNOWN_RULE_KEYS
    assert not unknown_keys, "Unknown keys: %s" % ", ".join(unknown_keys)

    # Build up the update in chunks and join them below.
    update_fragments = ["--append", chain_name]
    append = lambda *args: update_fragments.extend(args)

    proto = None
    if "protocol" in rule:
        proto = rule["protocol"]
        assert proto in ["tcp", "udp", "icmp", "icmpv6"]
        append("--protocol", proto)

    for dirn in ["src", "dst"]:
        # Some params use the long-form of the name.
        direction = "source" if dirn == "src" else "destination"

        # Network (CIDR).
        net_key = dirn + "_net"
        if net_key in rule:
            ip_or_cidr = rule[net_key]
            if (":" in ip_or_cidr) == (ip_version == 6):
                append("--%s" % direction, ip_or_cidr)

        # Tag, which maps to an ipset.
        tag_key = dirn + "_tag"
        if tag_key in rule:
            ipset_name = tag_to_ipset[rule[tag_key]]
            append("--match set", "--match-set", ipset_name, dirn)

        # Port lists/ranges, which we map to multiport.
        ports_key = dirn + "_ports"
        if ports_key in rule:
            assert proto in ["tcp", "udp"], "Protocol %s not supported with " \
                                            "%s" % (proto, ports_key)
            ports = ','.join([str(p) for p in rule[ports_key]])
            # multiport only supports 15 ports.
            # TODO: return multiple rules if we have more than one port
            assert ports.count(",") + ports.count(":") < 15, "Too many ports"
            append("--match multiport", "--%s-ports" % direction, ports)

    if "icmp_type" in rule:
        icmp_type = rule["icmp_type"]
        assert isinstance(icmp_type, int), "ICMP type should be an int"
        if proto == "icmp" and ip_version == 4:
            append("--match icmp", "--icmp-type", rule["icmp_type"])
        elif ip_version == 6:
            assert proto == "icmpv6"
            # Note variant spelling of icmp[v]6
            append("--match icmp6", "--icmpv6-type", rule["icmp_type"])

    # Add the action
    append("--jump", on_allow if rule.get("action", "allow") == "allow"
                              else on_deny)

    return " ".join(str(x) for x in update_fragments)
