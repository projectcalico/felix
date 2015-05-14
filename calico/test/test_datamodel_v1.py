# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
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
test.test_datamodel_v1
~~~~~~~~~~~~~~~~~~~~~~

Test data model key calculations etc.
"""

import logging
import mock
import unittest

from calico.datamodel_v1 import *


# Logger
log = logging.getLogger(__name__)


class TestDatamodel(unittest.TestCase):
    def test_rules_regex(self):
        m = RULES_KEY_RE.match("/calico/v1/policy/profile/prof1/rules")
        self.assertEqual(m.group("profile_id"), "prof1")
        m = RULES_KEY_RE.match("/calico/v1/policy/profile/prof1/rules/")
        self.assertEqual(m.group("profile_id"), "prof1")

        m = RULES_KEY_RE.match("/calico/v1/policy/profile/prof1/rule")
        self.assertFalse(m)
        m = RULES_KEY_RE.match("/calico/v1/host/")
        self.assertFalse(m)

    def test_dir_for_host(self):
        self.assertEqual(dir_for_host("foo"), "/calico/v1/host/foo")

    def test_dir_for_per_host_config(self):
        self.assertEqual(dir_for_per_host_config("foo"),
                         "/calico/v1/host/foo/config")

    def test_key_for_endpoint(self):
        self.assertEqual(
            key_for_endpoint("foo", "openstack", "wl1", "ep2"),
            "/calico/v1/host/foo/workload/openstack/wl1/endpoint/ep2")

    def test_key_for_profile(self):
        self.assertEqual(key_for_profile("prof1"),
                         "/calico/v1/policy/profile/prof1")

    def test_key_for_profile_rules(self):
        self.assertEqual(key_for_profile_rules("prof1"),
                         "/calico/v1/policy/profile/prof1/rules")

    def test_key_for_profile_tags(self):
        self.assertEqual(key_for_profile_tags("prof1"),
                         "/calico/v1/policy/profile/prof1/tags")

    def test_key_for_config(self):
        self.assertEqual(key_for_config("ConfigValue"),
                         "/calico/v1/config/ConfigValue")

    def test_del_action(self):
        del_action = delete_action("/calico/v1/whocares")
        expected = { 'type': DELETED_NONE }
        self.assertEqual(del_action, expected)

        for path in ("/calico", "/calico/", "/calico/v1", "/calico/v1/",
                     "/calico/v1/Ready", "/calico/v1/host", "/calico/v1/host/",
                     "/calico/v1/policy", "/calico/v1/policy/"):
            log.debug("Check deletion of path %r", path)
            del_action = delete_action(path)
            expected = { 'type': DELETED_ALL }
            self.assertEqual(del_action, expected)

        values = ["name", "with spaces", " _something-else_ "]

        for profile_id in values:
            path = "/calico/v1/policy/profile/%s/rules" % profile_id
            log.debug("Check deletion of path %r", path)
            del_action = delete_action(path)
            expected = { 'type': DELETED_RULES,
                         'profile': profile_id}
            self.assertEqual(del_action, expected)

            path = "/calico/v1/policy/profile/%s/tags" % profile_id
            log.debug("Check deletion of path %r", path)
            del_action = delete_action(path)
            expected = { 'type': DELETED_TAGS,
                         'profile': profile_id}
            self.assertEqual(del_action, expected)

            path = "/calico/v1/policy/profile/%s" % profile_id
            log.debug("Check deletion of path %r", path)
            del_action = delete_action(path)
            expected = { 'type': DELETED_PROFILE,
                         'profile': profile_id}
            self.assertEqual(del_action, expected)

            path = "/calico/v1/policy/profile/%s/" % profile_id
            log.debug("Check deletion of path %r", path)
            del_action = delete_action(path)
            expected = { 'type': DELETED_PROFILE,
                         'profile': profile_id}
            self.assertEqual(del_action, expected)

        for host in values:
            base = "/calico/v1/host/%s" % host
            for path in (base, base + "/", base + "/workload",
                         base + "/workload/"):
                log.debug("Check deletion of host %r", path)
                del_action = delete_action(path)
                expected = { 'type': DELETED_HOST,
                             'host': host}
                self.assertEqual(del_action, expected)

            for orch in values:
                base = "/calico/v1/host/%s/workload/%s" % (host, orch)
                for path in (base, base + "/"):
                    log.debug("Check deletion of orchestrator %r", path)
                    del_action = delete_action(path)
                    expected = { 'type': DELETED_ORCHESTRATOR,
                                 'host': host,
                                 'orchestrator': orch}
                    self.assertEqual(del_action, expected)

                for workload in values:
                    base = "/calico/v1/host/%s/workload/%s/%s" \
                           % (host, orch, workload)
                    for path in (base, base + "/", base + "/endpoint",
                                 base + "/endpoint/"):
                        log.debug("Check deletion of workload %r", path)
                        del_action = delete_action(path)
                        expected = { 'type': DELETED_WORKLOAD,
                                     'host': host,
                                     'orchestrator': orch,
                                     'workload': workload}
                        self.assertEqual(del_action, expected)

                    for ep_id in values:
                        path = "/calico/v1/host/%s/workload/%s/%s/endpoint/%s" \
                               % (host, orch, workload, ep_id)
                        log.debug("Check deletion of endpoint %r", path)
                        del_action = delete_action(path)
                        expected = { 'type': DELETED_ENDPOINT,
                                     'host': host,
                                     'orchestrator': orch,
                                     'workload': workload,
                                     'endpoint': ep_id}
                        self.assertEqual(del_action, expected)
