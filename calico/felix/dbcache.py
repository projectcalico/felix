# Copyright (c) Metaswitch Networks 2015. All rights reserved.

from collections import defaultdict
import logging
import socket


from calico.felix.actor import actor_event, Actor, wait_and_check
from calico.felix.fiptables import IPTABLES_V4_UPDATER
from calico.felix.frules import (tag_to_ipset_name, profile_to_chain_name,
                                 update_chain, get_endpoint_rules,
                                 program_profile_chains,
                                 CHAIN_FROM_ENDPOINT, CHAIN_TO_ENDPOINT,
                                 CHAIN_TO_PREFIX, CHAIN_FROM_PREFIX)
from calico.felix.ipsets import IpsetUpdater

_log = logging.getLogger(__name__)


OUR_HOSTNAME = socket.gethostname()


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


def extract_tags_from_profile(profile):
    tags = set()
    for in_or_out in ["inbound", "outbound"]:
        for rule in profile.get(in_or_out, []):
            tags.update(extract_tags_from_rule(rule))
    return tags


def extract_tags_from_rule(rule):
    return set([rule[key] for key in ["src_tag", "dst_tag"] if key in rule])


UPDATE_SEQUENCER = UpdateSequencer()

