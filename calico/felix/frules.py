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
from calico.felix.fiptables import IPTABLES_V4_UPDATER, IPTABLES_V6_UPDATER
import re

_log = logging.getLogger(__name__)


# Chain names
CHAIN_PREROUTING = "felix-PREROUTING"
CHAIN_INPUT = "felix-INPUT"
CHAIN_FORWARD = "felix-FORWARD"
CHAIN_TO_ENDPOINT = "felix-TO-ENDPOINT"
CHAIN_FROM_ENDPOINT = "felix-FROM-ENDPOINT"
CHAIN_TO_PREFIX = "felix-to-"
CHAIN_FROM_PREFIX = "felix-from-"
CHAIN_PROFILE_PREFIX = "felix-profile-"


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


def tag_to_ipset_name(tag_name):
    assert re.match(r'^\w+$', tag_name), "Tags must be alphanumeric for now"
    return "calico-tag-" + tag_name


def profile_to_chain_name(inbound_or_outbound, profile_id):
    return CHAIN_PROFILE_PREFIX + "%s-%s" % (profile_id, inbound_or_outbound)


def get_endpoint_rules(suffix, iface, ip_version, local_ips, mac, profile_id):
    to_chain_name = CHAIN_TO_PREFIX + suffix

    to_chain = ["--flush %s" % to_chain_name]
    if ip_version == 6:
        #  In ipv6 only, there are 6 rules that need to be created first.
        #  RETURN ipv6-icmp anywhere anywhere ipv6-icmptype 130
        #  RETURN ipv6-icmp anywhere anywhere ipv6-icmptype 131
        #  RETURN ipv6-icmp anywhere anywhere ipv6-icmptype 132
        #  RETURN ipv6-icmp anywhere anywhere ipv6-icmp router-advertisement
        #  RETURN ipv6-icmp anywhere anywhere ipv6-icmp neighbour-solicitation
        #  RETURN ipv6-icmp anywhere anywhere ipv6-icmp neighbour-advertisement
        #
        #  These rules are ICMP types 130, 131, 132, 134, 135 and 136, and can
        #  be created on the command line with something like :
        #     ip6tables -A plw -j RETURN --protocol ipv6-icmp --icmpv6-type 130
        for icmp_type in ["130", "131", "132", "134", "135", "136"]:
            to_chain.append("--append %s --jump RETURN "
                            "--protocol ipv6-icmp "
                            "--icmpv6-type %s" % (to_chain_name, icmp_type))
    to_chain.append("--append %s --match conntrack --ctstate INVALID "
                    "--jump DROP" % to_chain_name)

    # FIXME: Do we want conntrack RELATED,ESTABLISHED?
    to_chain.append("--append %s --match conntrack "
                    "--ctstate RELATED,ESTABLISHED --jump RETURN" %
                    to_chain_name)
    profile_in_chain = profile_to_chain_name("inbound", profile_id)
    to_chain.append("--append %s --jump %s" %
                    (to_chain_name, profile_in_chain))
    to_chain.append("--append %s --jump DROP" % to_chain_name)

    # Now the chain that manages packets from the interface...
    from_chain_name = CHAIN_FROM_PREFIX + suffix
    from_chain = ["--flush %s" % from_chain_name]
    if ip_version == 6:
        # In ipv6 only, allows all ICMP traffic from this endpoint to anywhere.
        from_chain.append("--append %s --protocol ipv6-icmp")

    # Conntrack rules.
    from_chain.append("--append %s --match conntrack --ctstate INVALID "
                    "--jump DROP" % from_chain_name)
    # FIXME: Do we want conntrack RELATED,ESTABLISHED?
    from_chain.append("--append %s --match conntrack "
                      "--ctstate RELATED,ESTABLISHED --jump RETURN" %
                      from_chain_name)

    if ip_version == 4:
        from_chain.append("--append %s --protocol udp --sport 68 --dport 67 "
                          "--jump RETURN" % from_chain_name)
    else:
        assert ip_version == 6
        from_chain.append("--append %s --protocol udp --sport 546 --dport 547 "
                          "--jump RETURN" % from_chain_name)

    # Anti-spoofing rules.  Only allow traffic from known (IP, MAC) pairs to
    # get to the profile chain, drop other traffic.
    profile_out_chain = profile_to_chain_name("outbound", profile_id)
    for ip in local_ips:
        cidr = "%s/32" % ip if ip_version == 4 else "%s/64" % ip
        # Note use of --goto rather than --jump; this means that when the
        # profile chain returns, it will return the chain that called us, not
        # this chain.
        from_chain.append("--append %s --src %s --match mac --mac-source %s "
                          "--goto %s" % (from_chain_name, cidr,
                                         mac.upper(), profile_out_chain))
    from_chain.append("--append %s --jump DROP" % from_chain_name)

    return [to_chain_name, from_chain_name], to_chain + from_chain


def install_global_rules(config, iface_prefix):
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
    iface_match = iface_prefix + "+"

    # The IPV4 nat table first. This must have a felix-PREROUTING chain.
    nat_pr = ["--flush %s" % CHAIN_PREROUTING]
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
    IPTABLES_V4_UPDATER.apply_updates("nat", [CHAIN_PREROUTING], nat_pr)

    # Ensure we have a rule that forces us through the chain we just created.
    rule = "PREROUTING --jump %s" % CHAIN_PREROUTING
    try:
        # Try to atomically delete and reinsert the rule, if we fail, we
        # assume it wasn't present and insert it.
        pr = ["--delete %s" % rule,
              "--insert %s" % rule]
        IPTABLES_V4_UPDATER.apply_updates("nat", [], pr)
    except CalledProcessError:
        _log.info("Failed to detect pre-routing rule, will insert it.")
        pr = ["--insert %s" % rule]
        IPTABLES_V4_UPDATER.apply_updates("nat", [], pr)

    # Now the filter table. This needs to have calico-filter-FORWARD and
    # calico-filter-INPUT chains, which we must create before adding any
    # rules that send to them.
    for iptables_updater in [IPTABLES_V4_UPDATER, IPTABLES_V6_UPDATER]:
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
            "--flush %s" % CHAIN_FORWARD,
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
            "--flush %s" % CHAIN_INPUT,
            "--append %s --jump %s --in-interface %s" %
                (CHAIN_INPUT, CHAIN_FROM_ENDPOINT, iface_match),
            "--append %s --jump ACCEPT --in-interface %s" %
                (CHAIN_INPUT, iface_match),
        ])

        iptables_updater.apply_updates("filter", req_chains, updates)


def program_profile_chains(profile_id, profile):
    for in_or_out in ["inbound", "outbound"]:
        chain_name = profile_to_chain_name(in_or_out,
                                           profile_id)
        update_chain(chain_name, profile[in_or_out])


def update_chain(name, rule_list, iptable="filter", async=False):
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
    return IPTABLES_V4_UPDATER.apply_updates(iptable, [name], fragments,
                                             async=async)


def rule_to_iptables_fragment(chain_name, rule, on_allow="ACCEPT",
                              on_deny="DROP"):
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
            append("--%s" % direction, ip_or_cidr)

        # Tag, which maps to an ipset.
        tag_key = dirn + "_tag"
        if tag_key in rule:
            ipset_name = tag_to_ipset_name(rule[tag_key])
            append("--match set", "--match-set", ipset_name, dirn)

        # Port lists/ranges, which we map to multiport.
        ports_key = dirn + "_ports"
        if ports_key in rule:
            assert proto in ["tcp", "udp"], "Protocol %s not supported with " \
                                            "%s" % (proto, ports_key)
            ports = ','.join([str(p) for p in rule[ports_key]])
            # multiport only supports 15 ports.
            assert ports.count(",") + ports.count(":") < 15, "Too many ports"
            append("--match multiport", "--%s-ports" % direction, ports)

    if "icmp_type" in rule:
        icmp_type = rule["icmp_type"]
        assert isinstance(icmp_type, int), "ICMP type should be an int"
        if proto == "icmp":
            append("--match icmp", "--icmp-type", rule["icmp_type"])
        else:
            assert proto == "icmpv6"
            # Note variant spelling of icmp[v]6
            append("--match icmp6", "--icmpv6-type", rule["icmp_type"])

    # Add the action
    append("--jump", on_allow if rule.get("action") == "allow" else on_deny)

    return " ".join(str(x) for x in update_fragments)
