# Copyright (c) Metaswitch Networks 2015. All rights reserved.

from collections import defaultdict
import functools
import logging
import socket


from calico.felix.actor import actor_event, Actor, wait_and_check
from calico.felix.frules import (profile_to_chain_name,
                                 update_chain, get_endpoint_rules,
                                 program_profile_chains,
                                 CHAIN_FROM_ENDPOINT, CHAIN_TO_ENDPOINT,
                                 CHAIN_TO_PREFIX, CHAIN_FROM_PREFIX,
                                 rules_to_chain_rewrite_lines)
from calico.felix.ipsets import IpsetUpdater

_log = logging.getLogger(__name__)


OUR_HOSTNAME = socket.gethostname()


class ActiveProfile(Actor):
    def __init__(self, profile_id, iptables_updaters):
        super(ActiveProfile, self).__init__()
        self.id = profile_id
        self._iptables_updaters = iptables_updaters
        self._profile = None
        """:type dict: filled in by first update"""
        self._tag_to_ip_set_name = None
        """:type dict[str, str]: current mapping from tag name to ipset name."""

    @actor_event
    def on_profile_update(self, profile, tag_to_ipset_name):
        """
        Update the programmed iptables configuration with the new
        profile
        """
        assert profile["id"] == self.id

        futures = self._update_chain(profile, "inbound", tag_to_ipset_name)
        futures += self._update_chain(profile, "outbound", tag_to_ipset_name)
        wait_and_check(futures)

        self._profile = profile
        self._tag_to_ip_set_name = tag_to_ipset_name

    @actor_event
    def remove(self):
        """
        Called to tell us that this profile is no longer needed.  Removes
        our iptables configuration.

        Thread safety: Caller should wait on the result of this method before
        creating a new ActiveProfile with the same name.  Otherwise, the
        delete calls in this method could be issued after the initialization
        of the new profile.
        """
        futures = []
        for direction in ["inbound", "outbound"]:
            chain_name = profile_to_chain_name(direction, self.id)
            for updater in self._iptables_updaters.values():
                f = updater.delete_chain(chain_name, async=True)
                futures.append(f)
        wait_and_check(futures)

        self._profile = None
        self._tag_to_ip_set_name = None

    def _update_chain(self, new_profile, direction, tag_to_ipset_name):
        new_rules = new_profile.get(direction, [])
        if (self._profile is None or
            new_rules != self._profile.get(direction) or
            tag_to_ipset_name != self._tag_to_ip_set_name):
            _log.debug("Update to %s affects %s rules.", self.id, direction)
            chain_name = profile_to_chain_name(direction, self.id)
            futures = []
            for version, ipt in self._iptables_updaters.iteritems():
                if version == 6:
                    _log.error("Ignoring v6")
                    continue
                updates = rules_to_chain_rewrite_lines(chain_name,
                                                       new_rules,
                                                       version,
                                                       tag_to_ipset_name,
                                                       on_allow="RETURN")
                f = ipt.apply_updates("filter", [chain_name], updates,
                                      async=True)
                futures.append(f)
            return futures
        else:
            _log.debug("Update to %s didn't affect %s rules.",
                       self.id, direction)


class UpdateSequencer(Actor):
    def __init__(self, ipset_pool, v4_updater, v6_updater):
        super(UpdateSequencer, self).__init__()

        self.ipset_pool = ipset_pool
        self.v4_updater = v4_updater
        self.v6_updater = v6_updater
        self.iptables_updaters = {
            4: v4_updater,
            6: v6_updater,
        }

        # Data.
        self.profiles_by_id = {}
        self.endpoints_by_id = {}

        # Indexes.
        self.endpoint_ids_by_tag = defaultdict(set)
        self.endpoint_ids_by_profile_id = defaultdict(set)
        self.local_endpoint_ids = set()
        self.active_profile_ids = set()

        # Child actors.
        self.active_profiles_by_id = {}
        self.active_ipsets_by_tag = {}
        self.profiles_to_reap = set()

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

        old_active_tags = set(self.active_ipsets_by_tag.keys())
        old_active_profile_ids = set(self.active_profiles_by_id.keys())

        # Stage 1: scan through endpoints to collect locals, tag members,
        # active profiles.
        _log.info("Applying snapshot; scanning endpoints.")
        new_local_endpoint_ids = set()
        new_endpoint_ids_by_tag = defaultdict(set)
        new_endpoint_ids_by_profile_id = defaultdict(set)
        new_active_profile_ids = set()
        for endpoint_id, endpoint in endpoints_by_id.iteritems():
            if endpoint["host"] == OUR_HOSTNAME:
                # Endpoint is local
                new_local_endpoint_ids.add(endpoint_id)
            profile_id = endpoint["profile_id"]
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
        new_active_tags_by_profile_id = {}
        for profile_id in new_active_profile_ids:
            profile = profiles_by_id[profile_id]
            tags = extract_tags_from_profile(profile)
            new_active_tags_by_profile_id[profile_id] = tags
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

        # Stage 4: queue updates to live tag ipsets.
        for tag, members in new_active_ipset_members_by_tag.iteritems():
            _log.debug("Updating ipset for tag %s", tag)
            ipset = self._get_or_create_ipset(tag)
            ipset.replace_members(members, async=True)  # Efficient update.

        # Clean up old ipsets.
        for unused_tag in old_active_tags - new_active_tags:
            ipset = self.active_ipsets_by_tag.pop(unused_tag)
            self.ipset_pool.return_ipset(ipset, async=True)

        # Stage 5: queue updates to live profile chains.
        for profile_id in new_active_profile_ids:
            profile = profiles_by_id[profile_id]
            active_profile = self._get_or_create_profile(profile_id)
            tag_mapping = {}
            for tag in new_active_tags_by_profile_id[profile_id]:
                ipset = self._get_or_create_ipset(tag)
                tag_mapping[tag] = ipset.name
            active_profile.on_profile_update(profile, tag_mapping, async=True)

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
                                                 endpoint["profile_id"])
            updates += self.active_endpoint_updates()
            # TODO: IPv6
            self.v4_updater.apply_updates("filter", chains, updates)

        # Stage 8: Clean up old profiles.
        for dead_profile_id in old_active_profile_ids - new_active_profile_ids:
            self._queue_profile_reap(dead_profile_id)

        # TODO Stage 9: program routing rules?

        _log.info("Finished applying snapshot.")

    def _queue_profile_reap(self, dead_profile_id):
        # FIXME reap, add (cancels reap), reap, add could fail: canceled reap calls back and looks like second one
        ap = self.active_profiles_by_id[dead_profile_id]
        self.profiles_to_reap.add(dead_profile_id)
        f = ap.remove(async=True)
        # We can't remove the profile until it's finished removing itself
        # so ask the result to call us back when it's done.  In the
        # meantime we might revive the profile.
        f.rawlink(functools.partial(self.on_active_profile_removed,
                                    dead_profile_id,
                                    async=True))

    @actor_event
    def on_active_profile_removed(self, profile_id):
        if profile_id in self.profiles_to_reap:
            _log.debug("Reaping profile %s", profile_id)
            self.profiles_to_reap.remove(profile_id)
            self.active_profiles_by_id.pop(profile_id, None)

    def _get_or_create_profile(self, profile_id):
        if profile_id not in self.active_profiles_by_id:
            ap = ActiveProfile(profile_id, self.iptables_updaters).start()
            self.active_profiles_by_id[profile_id] = ap
        # If the profile was queued for deletion, reinstate it.
        self.profiles_to_reap.discard(profile_id)
        return self.active_profiles_by_id[profile_id]

    def _get_or_create_ipset(self, tag):
        if tag not in self.active_ipsets_by_tag:
            ipset = self.ipset_pool.allocate_ipset(tag)
            self.active_ipsets_by_tag[tag] = ipset
        return self.active_ipsets_by_tag[tag]

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
            new_tags = set()
            self.profiles_by_id.pop(profile_id)
            if profile_id in self.active_profiles_by_id:
                self._queue_profile_reap(profile_id)
        else:
            new_tags = set(profile.get("tags", []))
            self.profiles_by_id[profile_id] = profile

        self._process_tag_updates(profile_id, old_tags, new_tags)

        if profile is not None:
            if self._profile_active(profile_id):
                ap = self.active_profiles_by_id[profile_id]
                tag_mapping = {}
                for tag in extract_tags_from_profile(profile):
                    ipset = self._get_or_create_ipset(tag)
                    tag_mapping[tag] = ipset.name
                ap.on_profile_update(profile, tag_mapping)
                # TODO: Remove orphaned ipsets.

        _log.info("Profile update: %s complete", profile_id)

    def _process_tag_updates(self, profile_id, old_tags, new_tags):
        """
        Updates the active ipsets associated with the change in tags
        of the given profile ID.
        """
        endpoint_ids = self.endpoint_ids_by_profile_id.get(profile_id, set())
        added_tags = new_tags - old_tags
        removed_tags = old_tags - new_tags
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
                                ipset.add_member(ip, async=True)
                            else:
                                ipset.remove_member(ip, async=True)

    def _profile_active(self, profile_id):
        return profile_id in self.active_profile_ids

    def _ensure_profile_ipsets_exist(self, profile):
        for tag in extract_tags_from_profile(profile):
            self._get_or_create_ipset(tag)

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
            new_profile_id = endpoint["profile_id"]
            new_profile = self.profiles_by_id[new_profile_id]
            new_tags = new_profile["tags"]
            old_ips_per_tag = defaultdict(set)

            if endpoint_id in self.endpoints_by_id:
                _log.debug("Update to existing endpoint %s.", endpoint_id)
                old_endpoint = self.endpoints_by_id[endpoint_id]
                if old_endpoint == endpoint:
                    _log.info("No change to endpoint, skipping.")
                    return
                old_profile_id = old_endpoint["profile_id"]
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
                        self.active_profile_ids.add(endpoint["profile_id"])
                    # TODO: GC unused chains

                chains, updates = get_endpoint_rules(
                    endpoint_id,
                    endpoint["interface_name"],
                    4,
                    endpoint["ip_addresses"],
                    endpoint["mac"],
                    endpoint["profile_id"])
                updates += self.active_endpoint_updates()
                # TODO: IPv6
                self.v4_updater.apply_updates("filter", chains, updates)

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



