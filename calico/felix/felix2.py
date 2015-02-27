# Copyright (c) Metaswitch Networks 2015. All rights reserved.

# Monkey-patch before we do anything else...
import json
from gevent import monkey
from gevent.event import AsyncResult

monkey.patch_all()

import logging
from collections import defaultdict
import re
from subprocess import CalledProcessError

import gevent
from gevent import subprocess
import etcd

from calico.felix.actor import actor_event, Actor

_log = logging.getLogger(__name__)

# etcd path regexes
PROFILE_RE = re.compile(
    r'^/calico/network/profile/(?P<profile_id>[^/]+)/policy')
ENDPOINT_RE = re.compile(
    r'^/calico/host/(?P<hostname>[^/]+)/endpoint/(?P<endpoint_id>[^/]+)')


# FIXME: Temporarily use localhost as only local hostname
OUR_HOSTNAME = "localhost"


class RulesActor(Actor):

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
            # Very first update, stash the profile ID and sync our state from
            # iptables.
            self.profile_id = profile["id"]
            self._load_rules_from_iptables()  # One-time load
        self._sync_rules_to_iptables()

    def _load_rules_from_iptables(self):
        pass

    def _sync_rules_to_iptables(self):
        pass


class IpsetActor(Actor):

    def __init__(self, name, set_type):
        super(IpsetActor, self).__init__()

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
        assert isinstance(members, set), "Expected members to be a set"
        self.members = members
        self._sync_to_ipset()

    @actor_event
    def add_member(self, member):
        self.members.add(member)
        self._sync_to_ipset()

    @actor_event
    def remove_member(self, member):
        self.members.remove(member)
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


class IptablesRestore(Actor):
    """
    Actor that maintains an iptables-restore subprocess for
    injecting rules into iptables.

    Note: due to the internal architecture of IP tables,
    multiple concurrent calls to iptables-restore can clobber
    each other.  Use one instance of this class.
    """

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
        restore_input = "\n".join(
            ["*%s" % table_name] +
            [":%s -" % c for c in required_chains] +
            update_calls +
            ["COMMIT\n"]
        )
        _log.debug("iptables-restore input:\n%s", restore_input)

        # TODO: Avoid big forks, keep the process alive for another update
        cmd = ["iptables-restore", "--noflush"]
        iptables_proc = subprocess.Popen(cmd,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        out, err = iptables_proc.communicate(restore_input)
        rc = iptables_proc.wait()
        if rc != 0:
            _log.error("Failed to run iptables-restore.\nOutput:%s\nError: %s",
                       out, err)
            raise CalledProcessError(cmd=cmd, returncode=rc)


IPTABLES_RESTORE = IptablesRestore()


def extract_tags_from_rule(rule):
    tags = set()
    for key in ["source_tag", "dest_tag"]:
        try:
            tags.add(rule[key])
        except KeyError:
            pass
    return tags


class DBCache(Actor):
    def __init__(self):
        super(DBCache, self).__init__()

        self.profiles_by_id = {}
        self.endpoints_by_id = {}
        self.endpoint_ids_by_tag = defaultdict(set)
        self.endpoint_ids_by_profile_id = defaultdict(set)
        self.local_endpoint_ids = set()

        self.active_ipsets_by_tag = {}
        self.active_chains_by_id = {}

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
            for rule in profile["inbound"]:
                new_active_tags.update(extract_tags_from_rule(rule))
            for rule in profile["outbound"]:
                new_active_tags.update(extract_tags_from_rule(rule))

        # Stage 3: look up IP addresses associated with endpoints.
        new_active_ipset_members_by_tag = defaultdict(set)
        for tag in new_active_tags:
            for endpoint_id in new_endpoint_ids_by_tag[tag]:
                endpoint = endpoints_by_id[endpoint_id]
                new_active_ipset_members_by_tag[tag].update(
                    endpoint.get("ip_addresses", []))

        # Stage 4: update live tag ipsets, creating any that are missing.
        # Since the ipset updates are async, collect the futures to wait on below.  We need them
        # all to exist before we update the rules to use them.

        # FIXME: Updating ipsets in-place may temporarily make inconsistencies vs old profiles.
        # Could "double buffer" ipsets and chains to avoid that.  Should be doable, just
        # return the current name via the Future and use it to update/create the profile chains.
        # However, it would double the occupancy of the ipsets and slow us down.
        #
        # Alternatively, could drop all traffic on profiles that are about to be modified
        # until we've fixed them up.
        #
        # Or, we could try to come up with a smarter algorithm.  I suspect that's not worth it.
        #
        # Shouldn't be an issue with non-snapshot updates since we sequence profile and endpoint
        # updates.
        futures = []
        for tag, members in new_active_ipset_members_by_tag:
            if tag in self.active_ipsets_by_tag:
                ipset = self.active_ipsets_by_tag[tag]
            else:
                ipset = IpsetActor("calico_tag_%s" % tag, "hash:ip")
                self.active_ipsets_by_tag[tag] = ipset
            f = ipset.replace_members(members)  # Does an efficient update.
            futures.append(f)
        while futures:
            futures.pop().get()

        # Stage 5: update live profile chains

        # Stage 6: update master rules to use all the profile chains.

        # Stage 7: program routing rules?


    @actor_event
    def on_profile_change(self, profile_id, profile):
        """
        Process an update to the given profile.  profile may be None if the
        profile was deleted.
        """
        if profile is None:
            # TODO: Handle deletion
            pass
        else:
            if profile_id not in self.active_chains_by_id:
                # Profile is not in use, just stash it.
                self.profiles_by_id[profile_id] = profile
            else:
                # Profile must be in use.
                old_profile = self.profiles_by_id[profile_id]
                if set(profile["tags"]) != set(old_profile["tags"]):
                    # Tags have changed, TODO track down the ipsets that need
                    # to be updated.
                    _log.debug("Tags of profile %s have changed.", profile_id)
                if profile["inbound"] != old_profile["inbound"]:
                    # TODO Handle rule updates
                    pass
                if profile["outbound"] != old_profile["outbound"]:
                    # TODO Handle rule updates
                    pass

    @actor_event
    def on_endpoint_change(self, endpoint_id, endpoint):
        """
        Process an update to the given endpoint.  endpoint may be None if
        the endpoint was deleted.
        """
        if endpoint is None:
            # TODO Handle deletion.
            pass
        else:
            # New or updated endpoint.
            pass


DB_CACHE = DBCache()


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


def rule_to_iptables_update(chain_name, rule, on_allow="ACCEPT",
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
    append = update_fragments.append

    proto = None
    if "protocol" in rule:
        proto = rule["protocol"]
        assert proto in ["tcp", "udp", "icmp", "icmpv6"]
        append("--protocol")
        append(proto)

    for dirn in ["src", "dst"]:
        direction = "source" if dirn == "src" else "destination"
        # Network (CIDR).
        net_key = dirn + "_net"
        if net_key in rule:
            network = rule[net_key]
            append("--%s" % direction)
            append(network)

        # Tag, which maps to an ipset.
        tag_key = dirn + "_tag"
        if tag_key in rule:
            ipset = tag_to_ipset_name(rule[tag_key])
            append("--match set")  # Note: "set" is param to --match
            append("--match-set")  # Note: "--match-set" is param to "set"
            append(ipset)
            append(dirn)

        # Port lists/ranges, which we map to multiport.
        ports_key = dirn + "_ports"
        if ports_key in rule:
            assert proto in ["tcp", "udp"], "Protocol %s not supported" % proto
            ports = ','.join([str(p) for p in rule[ports_key]])
            # multiport only supports 15 ports.
            assert ports.count(",") + ports.count(":") < 15, "Too many ports"
            append("--match multiport")
            append("--%s-ports" % direction)
            append(ports)

    if "icmp_type" in rule:
        icmp_type = rule["icmp_type"]
        assert isinstance(icmp_type, int), "ICMP type should be an int"
        if proto == "icmp":
            append("--match icmp")
            append("--icmp-type")
            append(rule["icmp_type"])
        else:
            assert proto == "icmpv6"
            append("--match icmp6")
            append("--icmpv6-type")  # Param has different spelling to match.
            append(rule["icmp_type"])

    # Add the action
    append("--jump")
    if rule["action"] == "allow":
        append(on_allow)
    else:
        assert rule["action"] == "deny"
        append(on_deny)

    return " ".join(str(x) for x in update_fragments)


def tag_to_ipset_name(tag_name):
    assert re.match(r'^\w+$', tag_name), "Tags must be alphanumeric for now"
    return tag_name


def monitor_etcd():
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

    # Actually apply the snapshot.  The DBCache will apply deltas as
    # appropriate.  Grab the future in case it raises an error.
    f_apply_snap = DB_CACHE.apply_snapshot(profiles_by_id, endpoints_by_id)
    del profiles_by_id
    del endpoints_by_id

    wait_index = initial_dump.etcd_index
    while True:
        if f_apply_snap and f_apply_snap.ready():
            # Snapshot application finished, check for exceptions.
            _log.info("Snapshot application finished.")
            f_apply_snap.get_nowait()
            f_apply_snap = None
        # TODO Handle deletions.
        # TODO Handle read getting too far behind (have to resync or die)
        response = client.read("/calico/",
                               wait=True,
                               waitIndex=wait_index,
                               recursive=True)
        profile_id, profile = parse_if_profile(response)
        if profile_id:
            DB_CACHE.on_profile_change(profile_id, profile)
            continue
        endpoint_id, endpoint = parse_if_endpoint(response)
        if endpoint_id:
            DB_CACHE.on_endpoint_change(endpoint_id, endpoint)
            continue


def parse_if_endpoint(etcd_node):
    m = ENDPOINT_RE.match(etcd_node.key)
    if m:
        # Got an endpoint.
        endpoint_id = m.group("endpoint_id")
        hostname = m.group("hostname")
        endpoint = json.loads(etcd_node.value)
        endpoint["host"] = hostname
        return endpoint_id, endpoint
    return None, None


def parse_if_profile(etcd_node):
    m = PROFILE_RE.match(etcd_node.key)
    if m:
        # Got a profile.
        profile_id = m.group("profile_id")
        profile = json.loads(etcd_node.value)
        return profile_id, profile
    return None, None


def main():
    logging.basicConfig(level=logging.DEBUG)
    gevent.spawn(monitor_etcd).join()
