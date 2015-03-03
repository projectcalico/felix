# Copyright (c) Metaswitch Networks 2015. All rights reserved.

# Monkey-patch before we do anything else...
from gevent import monkey
monkey.patch_all()

from collections import defaultdict
import json
import logging
import re
import socket
from subprocess import CalledProcessError
import sys

import etcd
from etcd import EtcdException
import gevent
from gevent import subprocess

from calico.felix.actor import actor_event, Actor, wait_and_check
from calico.felix.config import Config

_log = logging.getLogger(__name__)

# etcd path regexes
PROFILE_RE = re.compile(
    r'^/calico/network/profile/(?P<profile_id>[^/]+)/policy')
ENDPOINT_RE = re.compile(
    r'^/calico/host/(?P<hostname>[^/]+)/endpoint/(?P<endpoint_id>[^/]+)')


OUR_HOSTNAME = socket.gethostname()


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

        self._load_from_ipset()

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


# Chain names
CHAIN_PREROUTING = "felix-PREROUTING"
CHAIN_INPUT = "felix-INPUT"
CHAIN_FORWARD = "felix-FORWARD"
CHAIN_TO_ENDPOINT = "felix-TO-ENDPOINT"
CHAIN_FROM_ENDPOINT = "felix-FROM-ENDPOINT"
CHAIN_TO_PREFIX = "felix-to-"
CHAIN_FROM_PREFIX = "felix-from-"
CHAIN_PROFILE_PREFIX = "felix-profile-"


class IptablesUpdater(Actor):
    """
    Actor that maintains an iptables-restore subprocess for
    injecting rules into iptables.

    Note: due to the internal architecture of IP tables,
    multiple concurrent calls to iptables-restore can clobber
    each other.  Use one instance of this class.
    """
    def __init__(self, ip_version=4):
        super(IptablesUpdater, self).__init__()
        if ip_version == 4:
            self.cmd_name = "iptables-restore"
        else:
            assert ip_version == 6
            self.cmd_name = "ip6tables-restore"

    @actor_event
    def apply_updates(self, table_name, required_chains, update_calls):
        """
        Atomically apply a set of updates to an iptables table.

        :param table_name: one of "raw" "mangle" "filter" "nat".
        :param required_chains: list of chains that the updates
               operate on; they will be created if needed.
        :param update_calls: list of iptables-style update calls,
               e.g. ["-A chain_name -j ACCEPT"] If rewriting a
               whole chain, start with "-F chain_name" to flush
               the chain.
        :returns an AsyncResult that may raise CalledProcessError
                 if a problem occurred.
        """
        # Run iptables-restore in noflush mode so that it doesn't
        # blow away all the tables we're not touching.

        # Valid input looks like this.
        #
        # *table
        # :chain_name
        # :chain_name_2
        # -F chain_name
        # -A chain_name -j ACCEPT
        # COMMIT
        #
        # The chains are created if they don't exist.
        chains = [":%s -" % c if isinstance(c, basestring) else ":%s %s" % c
                  for c in required_chains]
        restore_input = "\n".join(
            ["*%s" % table_name] +
            chains +
            update_calls +
            ["COMMIT\n"]
        )
        _log.debug("iptables-restore input:\n%s", restore_input)
        cmd = [self.cmd_name, "--noflush"]
        iptables_proc = subprocess.Popen(cmd,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        out, err = iptables_proc.communicate(restore_input)
        rc = iptables_proc.wait()
        if rc != 0:
            _log.error("Failed to run %s.\nOutput:%s\nError: %s",
                       self.cmd_name, out, err)
            raise CalledProcessError(cmd=cmd, returncode=rc)


IPTABLES_V4_UPDATER = IptablesUpdater(ip_version=4)
IPTABLES_V6_UPDATER = IptablesUpdater(ip_version=6)


def extract_tags_from_profile(profile):
    tags = set()
    for in_or_out in ["inbound", "outbound"]:
        for rule in profile.get(in_or_out, []):
            tags.update(extract_tags_from_rule(rule))
    return tags


def extract_tags_from_rule(rule):
    return set([rule[key] for key in ["src_tag", "dst_tag"] if key in rule])


class UpdateSequencer(Actor):
    def __init__(self):
        super(UpdateSequencer, self).__init__()

        # Data.
        self.profiles_by_id = {}
        self.endpoints_by_id = {}

        # Indexes.
        self.endpoint_ids_by_tag = defaultdict(set)
        self.endpoint_ids_by_profile_id = defaultdict(set)
        self.local_endpoint_ids = set()
        self.active_profile_ids = set()

        # Child actors.
        self.active_ipsets_by_tag = {}

    @actor_event
    def apply_snapshot(self, profiles_by_id, endpoints_by_id):
        """
        Replaces the whole cache state with the input.  Applies deltas vs the
        current active state.
        """

        # While we cache the whole lot, we need to track the following to
        # apply deltas:
        #
        # - changes in the list of local endpoints.
        # - changes in the rules that are active for those endpoints.
        # - changes in the tag memberships of tags used in the active profiles.

        # Stage 1: scan through endpoints to collect locals, tag members,
        # active profiles.
        _log.info("Applying snapshot; scanning endpoints.")
        new_local_endpoint_ids = set()
        new_endpoint_ids_by_tag = defaultdict(set)
        new_endpoint_ids_by_profile_id = defaultdict(set)
        new_active_profile_ids = set()
        for endpoint_id, endpoint_data in endpoints_by_id.iteritems():
            if endpoint_data["host"] == OUR_HOSTNAME:
                # Endpoint is local
                new_local_endpoint_ids.add(endpoint_id)
            profile_id = endpoint_data["profile"]
            profile = profiles_by_id[profile_id]
            new_active_profile_ids.add(profile_id)
            new_endpoint_ids_by_profile_id[profile_id].add(endpoint_id)
            for tag in profile["tags"]:
                new_endpoint_ids_by_tag[tag].add(endpoint_id)
        _log.info("Scanned %s endpoints, %s local endpoints, %s tags, %s "
                  "active profiles.",
                  len(endpoints_by_id), len(new_local_endpoint_ids),
                  len(new_endpoint_ids_by_tag), len(new_active_profile_ids))

        # Stage 2: scan active profiles looking for in-use tags (which we'll
        # turn into ipsets).
        new_active_tags = set()
        for profile_id in new_active_profile_ids:
            profile = profiles_by_id[profile_id]
            tags = extract_tags_from_profile(profile)
            new_active_tags.update(tags)
            _log.debug("In-use tags for profile %s: %s", profile_id, tags)

        # Stage 3: look up IP addresses associated with endpoints.
        new_active_ipset_members_by_tag = defaultdict(set)
        for tag in new_active_tags:
            _log.debug("Determining IPs for tag %s", tag)
            # Slight subtlety: accessing new_active_ipset_members_by_tag[tag]
            # ensures it gets created even if there are no IPs.
            members = new_active_ipset_members_by_tag[tag]
            for endpoint_id in new_endpoint_ids_by_tag[tag]:
                endpoint = endpoints_by_id[endpoint_id]
                members.update(endpoint.get("ip_addresses", []))
            _log.debug("IPs for tag %s: %s", tag, 
                       new_active_ipset_members_by_tag[tag])

        # Stage 4: update live tag ipsets, creating any that are missing.
        # Since the ipset updates are async, collect the futures to wait on
        # below.  We need them all to exist before we update the rules to use
        # them.

        # FIXME: Updating ipsets in-place may temporarily make inconsistencies
        # vs old profiles.  Could "double buffer" ipsets and chains to avoid
        # that.  Should be doable, just return the current name via the Future
        # and use it to update/create the profile chains. However, it would
        # double the occupancy of the ipsets and slow us down.
        #
        # Alternatively, could drop all traffic on profiles that are about to
        # be modified until we've fixed them up.
        #
        # Or, we could try to come up with a smarter algorithm.  I suspect
        # that's not worth it.
        #
        # Shouldn't be an issue with non-snapshot updates since we sequence
        # profile and endpoint updates.
        futures = []
        for tag, members in new_active_ipset_members_by_tag.iteritems():
            _log.debug("Updating ipset for tag %s", tag)
            if tag in self.active_ipsets_by_tag:
                ipset = self.active_ipsets_by_tag[tag]
            else:
                ipset = IpsetUpdater(tag_to_ipset_name(tag), "hash:ip").start()
                self.active_ipsets_by_tag[tag] = ipset
            f = ipset.replace_members(members, async=True)  # Efficient update.
            futures.append(f)
        wait_and_check(futures)

        # Stage 5: update live profile chains
        for profile_id in new_active_profile_ids:
            _log.debug("Updating live profile chain for %s", profile_id)
            profile = profiles_by_id[profile_id]
            for in_or_out in ["inbound", "outbound"]:
                chain_name = profile_to_chain_name(in_or_out, profile_id)
                rules = profile[in_or_out]
                update_chain(chain_name, rules)

        # Stage 6: replace the database with the new snapshot.
        _log.info("Replacing state with new snapshot.")
        self.profiles_by_id = profiles_by_id
        self.endpoints_by_id = endpoints_by_id
        self.endpoint_ids_by_tag = new_endpoint_ids_by_tag
        self.endpoint_ids_by_profile_id = new_endpoint_ids_by_profile_id
        self.local_endpoint_ids = new_local_endpoint_ids
        self.active_profile_ids = new_active_profile_ids

        # Stage 7: update master rules to use all the profile chains.
        for endpoint_id in new_local_endpoint_ids:
            endpoint = endpoints_by_id[endpoint_id]
            chains, updates = get_endpoint_rules(endpoint_id,
                                                 endpoint["interface_name"],
                                                 4,
                                                 endpoint["ip_addresses"],
                                                 endpoint["mac"],
                                                 endpoint["profile"])
            updates += self.active_endpoint_updates()
            IPTABLES_V4_UPDATER.apply_updates("filter", chains, updates)

        # TODO Stage 8: program routing rules?

        _log.info("Finished applying snapshot.")

    def _process_tag_updates(self, profile_id, old_tags, new_tags):
        """
        Updates the active ipsets associated with the change in tags
        of the given profile ID.
        """
        endpoint_ids = self.endpoint_ids_by_profile_id.get(profile_id,
                                                           set())
        added_tags = new_tags - old_tags
        removed_tags = old_tags - new_tags
        futures = []
        for added, upd_tags in [(True, added_tags), (False, removed_tags)]:
            for tag in upd_tags:
                if added:
                    self.endpoint_ids_by_tag[tag] |= endpoint_ids
                else:
                    self.endpoint_ids_by_tag[tag] -= endpoint_ids
                if tag in self.active_ipsets_by_tag:
                    # Tag is in-use, update its members.
                    ipset = self.active_ipsets_by_tag[tag]
                    for endpoint_id in endpoint_ids:
                        endpoint = self.endpoints_by_id[endpoint_id]
                        for ip in endpoint["ip_addresses"]:
                            if added:
                                f = ipset.add_member(ip, async=True)
                            else:
                                f = ipset.remove_member(ip, async=True)
                            futures.append(f)
        wait_and_check(futures)

    @actor_event
    def on_profile_change(self, profile_id, profile):
        """
        Process an update to the given profile.  profile may be None if the
        profile was deleted.
        """
        _log.info("Profile update: %s", profile_id)

        # Lookup old profile, if any.
        old_profile = self.profiles_by_id.get(profile_id, {"tags": []})
        old_tags = set(old_profile["tags"])

        if profile is None:
            _log.info("Delete for profile %s", profile_id)
            if self._profile_active(profile_id):
                raise ValueError("Inconsistent update: attempt to remove "
                                 "profile %s, which is active." % profile_id)
            new_tags = set()
            del self.profiles_by_id[profile_id]
        else:
            new_tags = set(profile.get("tags", []))
            self.profiles_by_id[profile_id] = profile

        self._process_tag_updates(profile_id, old_tags, new_tags)

        if profile is not None:
            # Create any missing ipsets.  Must do this before we reference them
            # in rules below.
            self._ensure_profile_ipsets_exist(profile)
            # TODO: Remove orphaned ipsets.

            # Update the rules.
            if self._profile_active(profile_id):
                for in_or_out in ["inbound", "outbound"]:
                    # Profile in use, look for rule changes.
                    if profile[in_or_out] != old_profile.get(in_or_out):
                        program_profile_chains(profile_id, profile)
                        break

        _log.info("Profile update: %s complete", profile_id)

    def _profile_active(self, profile_id):
        return profile_id in self.active_profile_ids

    def _ensure_profile_ipsets_exist(self, profile):
        futures = []
        for tag in extract_tags_from_profile(profile):
            if tag not in self.active_ipsets_by_tag:
                members = set()
                for endpoint_id in self.endpoint_ids_by_tag[tag]:
                    endpoint = self.endpoints_by_id[endpoint_id]
                    members.update(endpoint.get("ip_addresses", []))
                ipset = IpsetUpdater(tag_to_ipset_name(tag), "hash:ip").start()
                self.active_ipsets_by_tag[tag] = ipset
                f = ipset.replace_members(members, async=True)
                futures.append(f)
        wait_and_check(futures)

    @actor_event
    def on_endpoint_change(self, endpoint_id, endpoint):
        """
        Process an update to the given endpoint.  endpoint may be None if
        the endpoint was deleted.
        """
        _log.info("Endpoint update: %s", endpoint_id)
        if endpoint is None:
            # TODO Handle deletion.
            pass
        else:
            new_profile_id = endpoint["profile"]
            new_profile = self.profiles_by_id[new_profile_id]
            new_tags = new_profile["tags"]
            old_ips_per_tag = defaultdict(set)

            if endpoint_id in self.endpoints_by_id:
                _log.debug("Update to existing endpoint %s.", endpoint_id)
                old_endpoint = self.endpoints_by_id[endpoint_id]
                if old_endpoint == endpoint:
                    _log.info("No change to endpoint, skipping.")
                    return
                old_profile_id = old_endpoint["profile"]
                old_profile = self.profiles_by_id[old_profile_id]
                old_tags = old_profile["tags"]

                # Find the endpoint's previous contribution to the ipsets.
                for tag in old_tags:
                    old_ips_per_tag[tag].update(old_endpoint["ip_addresses"])
                    self.endpoint_ids_by_tag[tag].remove(endpoint_id)
                # Remove from the index, we'll fix up below.  No race,
                # we can't be interrupted.
                self.endpoint_ids_by_profile_id[old_profile_id].remove(
                    endpoint_id)
            else:
                # New endpoint, implicitly had no tags before.
                _log.info("New endpoint: %s", endpoint_id)
                old_tags = []
                old_profile_id = None

            # Figure out current contribution to tags.
            _log.debug("Need to sync tags.")
            new_ips_per_tag = defaultdict(set)
            for tag in new_tags:
                new_ips_per_tag[tag].update(endpoint["ip_addresses"])
                self.endpoint_ids_by_tag[tag].add(endpoint_id)

            # Diff the set of old vs new IP addresses and apply deltas.
            futures = []
            for tag in set(old_tags + new_tags):
                if tag not in self.active_ipsets_by_tag:
                    # ipset isn't in use on this host, skip.
                    continue
                ipset = self.active_ipsets_by_tag[tag]
                for ip in old_ips_per_tag[tag] - new_ips_per_tag[tag]:
                    _log.debug("Removing %s from ipset for %s", ip, tag)
                    f = ipset.remove_member(ip, async=True)
                    futures.append(f)
                for ip in new_ips_per_tag[tag] - old_ips_per_tag[tag]:
                    _log.debug("Adding %s to ipset for %s", ip, tag)
                    f = ipset.add_member(ip, async=True)
                    futures.append(f)
            wait_and_check(futures)

            self.endpoint_ids_by_profile_id[new_profile_id].add(endpoint_id)
            self.endpoints_by_id[endpoint_id] = endpoint

            if endpoint["host"] == OUR_HOSTNAME:
                # Create any missing ipsets.
                _log.info("Endpoint is local, checking profile.")
                self.local_endpoint_ids.add(endpoint_id)
                self._ensure_profile_ipsets_exist(new_profile)

                if new_profile_id not in self.active_profile_ids:
                    program_profile_chains(new_profile_id, new_profile)

                if old_profile_id and old_profile_id != new_profile_id:
                    # Old profile may be unused. Recalculate.
                    _log.debug("Recalculating active_profile_ids index.")
                    self.active_profile_ids = set()
                    for endpoint_id in self.local_endpoint_ids:
                        endpoint = self.endpoints_by_id[endpoint_id]
                        self.active_profile_ids.add(endpoint["profile"])
                    # TODO: GC unused chains

                chains, updates = get_endpoint_rules(
                    endpoint_id,
                    endpoint["interface_name"],
                    4,
                    endpoint["ip_addresses"],
                    endpoint["mac"],
                    endpoint["profile"])
                updates += self.active_endpoint_updates()
                IPTABLES_V4_UPDATER.apply_updates("filter", chains, updates)

        _log.info("Endpoint update complete.")

    def active_endpoint_updates(self):
        updates = [
            "--flush " + CHAIN_FROM_ENDPOINT,
            "--flush " + CHAIN_TO_ENDPOINT,
        ]
        for endpoint_id in self.local_endpoint_ids:
            endpoint = self.endpoints_by_id[endpoint_id]
            iface = endpoint["interface_name"]
            to_chain_name = CHAIN_TO_PREFIX + endpoint_id
            from_chain_name = CHAIN_FROM_PREFIX + endpoint_id

            # Add rule to global chain to direct traffic to the
            # endpoint-specific one.
            updates.append("--append %s --out-interface %s --goto %s" %
                           (CHAIN_TO_ENDPOINT, iface, to_chain_name))
            updates.append("--append %s --in-interface %s --goto %s" %
                           (CHAIN_FROM_ENDPOINT, iface, from_chain_name))
            # FIXME: should we drop at end of this?
        return updates

UPDATE_SEQUENCER = UpdateSequencer()


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


def tag_to_ipset_name(tag_name):
    assert re.match(r'^\w+$', tag_name), "Tags must be alphanumeric for now"
    return "calico-tag-" + tag_name


def profile_to_chain_name(inbound_or_outbound, profile_id):
    return CHAIN_PROFILE_PREFIX + "%s-%s" % (profile_id, inbound_or_outbound)


def watch_etcd():
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
    f_apply_snap = UPDATE_SEQUENCER.apply_snapshot(profiles_by_id,
                                                   endpoints_by_id)
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
            UPDATE_SEQUENCER.on_profile_change(profile_id, profile,
                                               async=True)
            continue
        endpoint_id, endpoint = parse_if_endpoint(response)
        if endpoint_id:
            _log.info("Scheduling endpoint update %s", endpoint_id)
            UPDATE_SEQUENCER.on_endpoint_change(endpoint_id, endpoint,
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


class FakeConfig(object):
    pass


def _main_greenlet():
    # TODO: Load config
    config = FakeConfig()
    config.METADATA_IP = "127.0.0.1"
    config.METADATA_PORT = 8080
    iface_prefix = "tap"

    UPDATE_SEQUENCER.start()
    IPTABLES_V4_UPDATER.start()
    IPTABLES_V6_UPDATER.start()
    greenlets = [UPDATE_SEQUENCER.greenlet,
                 IPTABLES_V4_UPDATER.greenlet,
                 IPTABLES_V6_UPDATER.greenlet,
                 gevent.spawn(watchdog)]

    # Install the global rules before we start polling for updates.
    install_global_rules(config, iface_prefix)

    # Start polling for updates.
    greenlets.append(gevent.spawn(watch_etcd))

    while True:
        stopped_greenlets_iter = gevent.iwait(greenlets)
        try:
            stopped_greenlet = next(stopped_greenlets_iter)
            stopped_greenlet.get()
        except Exception:
            _log.exception("Greenlet failed: %s", stopped_greenlet)
        else:
            _log.error("Greenlet unexpectedly returned.")
        gevent.sleep(1)
        _log.error("Re-spawning.")
        # FIXME this isn't working!!  It starts it at the same point!
        stopped_greenlet.start()


def watchdog():
    while True:
        _log.info("Still alive")
        gevent.sleep(20)


def main():
    log_level = logging.DEBUG if '-d' in sys.argv else logging.INFO
    logging.basicConfig(level=log_level,
                        format="%(levelname).1s %(asctime)s "
                               "%(process)s|%(thread)x "
                               "%(filename)s:%(funcName)s:%(lineno)d "
                               "%(message)s")
    _log.info("Starting up")
    gevent.spawn(_main_greenlet).join()  # Should never return
