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
test.test_common
~~~~~~~~~~~

Test common utility code.
"""
import logging
import mock
import os
import unittest

import calico.common as common


# Logger
log = logging.getLogger(__name__)

class TestCommon(unittest.TestCase):
    def setUp(self):
        self.m_config = mock.Mock()
        self.m_config.IFACE_PREFIX = "tap"

    def tearDown(self):
        pass

    def test_validate_port(self):
        self.assertFalse(common.validate_port(-1))
        self.assertFalse(common.validate_port(0))
        self.assertTrue(common.validate_port(3))
        self.assertTrue(common.validate_port(3))
        self.assertTrue(common.validate_port(65535))
        self.assertFalse(common.validate_port(65536))
        self.assertFalse(common.validate_port("-1"))
        self.assertFalse(common.validate_port("0"))
        self.assertTrue(common.validate_port("3"))
        self.assertTrue(common.validate_port("3"))
        self.assertTrue(common.validate_port("65535"))
        self.assertFalse(common.validate_port("65536"))
        self.assertFalse(common.validate_port("1-10"))
        self.assertFalse(common.validate_port("blah"))

    def test_validate_endpoint_mainline(self):
        endpoint = {
            "state": "active",
            "name": "tap1234",
            "mac": "AA:bb:cc:dd:ee:ff",
            "ipv4_nets": ["10.0.1/32"],
            "ipv4_gateway": "11.0.0.1",
            "ipv6_nets": ["2001:0::1/64"],
            "ipv6_gateway": "fe80:0::1",
            "profile_id": "prof1",
        }
        common.validate_endpoint(self.m_config, endpoint)
        self.assertEqual(endpoint, {
            'state': 'active',
            'name': 'tap1234',
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ipv4_nets': ['10.0.1.0/32'],
            'ipv4_gateway': '11.0.0.1',
            'ipv6_nets': ['2001::1/64'],
            'ipv6_gateway': 'fe80::1',
            'profile_id': 'prof1',
        })

    def test_validate_rules(self):
        rules = {
            "inbound_rules": [
                {"protocol": "tcp", "ip_version": 4, "src_net": "10/8",
                 "dst_net": "11.0/16", "src_ports": [10, "11:12"],
                 "action": "allow"},
                {"protocol": "tcp", "src_net": None},
            ],
            "outbound_rules": [
                {"protocol": "tcp", "ip_version": 6,
                 "src_net": "2001:0::1/128", "dst_net": "2001:0::/64",
                 "icmp_type": 7, "icmp_code": 10,
                 "action": "deny"}
            ],
        }
        common.validate_rules(rules)
        # Check IPs get made canonical.
        self.assertEqual(rules, {
            "inbound_rules": [
                {"protocol": "tcp", "ip_version": 4, "src_net": "10.0.0.0/8",
                 "dst_net": "11.0.0.0/16", "src_ports": [10, "11:12"],
                 "action": "allow"},
                {"protocol": "tcp"},
            ],
            "outbound_rules": [
                {"protocol": "tcp", "ip_version": 6,
                 "src_net": "2001::1/128", "dst_net": "2001::/64",
                 "icmp_type": 7, "icmp_code": 10,
                 "action": "deny"}
            ],
        })

    def test_validate_ip_addr(self):
        self.assertTrue(common.validate_ip_addr("1.2.3.4", 4))
        self.assertFalse(common.validate_ip_addr("1.2.3.4.5", 4))
        self.assertFalse(common.validate_ip_addr("1.2.3.4/32", 4))
        self.assertTrue(common.validate_ip_addr("1.2.3", 4))
        self.assertFalse(common.validate_ip_addr("bloop", 4))
        self.assertFalse(common.validate_ip_addr("::", 4))
        self.assertFalse(common.validate_ip_addr("2001::abc", 4))
        self.assertFalse(common.validate_ip_addr("2001::a/64", 4))

        self.assertFalse(common.validate_ip_addr("1.2.3.4", 6))
        self.assertFalse(common.validate_ip_addr("1.2.3.4.5", 6))
        self.assertFalse(common.validate_ip_addr("1.2.3.4/32", 6))
        self.assertFalse(common.validate_ip_addr("1.2.3", 6))
        self.assertFalse(common.validate_ip_addr("bloop", 6))
        self.assertTrue(common.validate_ip_addr("::", 6))
        self.assertTrue(common.validate_ip_addr("2001::abc", 6))
        self.assertFalse(common.validate_ip_addr("2001::a/64", 6))

        self.assertTrue(common.validate_ip_addr("1.2.3.4", None))
        self.assertFalse(common.validate_ip_addr("1.2.3.4.5", None))
        self.assertFalse(common.validate_ip_addr("1.2.3.4/32", None))
        self.assertTrue(common.validate_ip_addr("1.2.3", None))
        self.assertFalse(common.validate_ip_addr("bloop", None))
        self.assertTrue(common.validate_ip_addr("::", None))
        self.assertTrue(common.validate_ip_addr("2001::abc", None))
        self.assertFalse(common.validate_ip_addr("2001::a/64", None))

        self.assertFalse(common.validate_ip_addr(None, None))

    def test_validate_cidr(self):
        self.assertTrue(common.validate_cidr("1.2.3.4", 4))
        self.assertFalse(common.validate_cidr("1.2.3.4.5", 4))
        self.assertTrue(common.validate_cidr("1.2.3.4/32", 4))
        self.assertTrue(common.validate_cidr("1.2.3", 4))
        self.assertFalse(common.validate_cidr("bloop", 4))
        self.assertFalse(common.validate_cidr("::", 4))
        self.assertFalse(common.validate_cidr("2001::abc", 4))
        self.assertFalse(common.validate_cidr("2001::a/64", 4))

        self.assertFalse(common.validate_cidr("1.2.3.4", 6))
        self.assertFalse(common.validate_cidr("1.2.3.4.5", 6))
        self.assertFalse(common.validate_cidr("1.2.3.4/32", 6))
        self.assertFalse(common.validate_cidr("1.2.3", 6))
        self.assertFalse(common.validate_cidr("bloop", 6))
        self.assertTrue(common.validate_cidr("::", 6))
        self.assertTrue(common.validate_cidr("2001::abc", 6))
        self.assertTrue(common.validate_cidr("2001::a/64", 6))

        self.assertTrue(common.validate_cidr("1.2.3.4", None))
        self.assertFalse(common.validate_cidr("1.2.3.4.5", None))
        self.assertTrue(common.validate_cidr("1.2.3.4/32", None))
        self.assertTrue(common.validate_cidr("1.2.3", None))
        self.assertFalse(common.validate_cidr("bloop", None))
        self.assertTrue(common.validate_cidr("::", None))
        self.assertTrue(common.validate_cidr("2001::abc", None))
        self.assertTrue(common.validate_cidr("2001::a/64", None))

        self.assertFalse(common.validate_cidr(None, None))

    def test_canonicalise_ip(self):
        self.assertTrue(common.canonicalise_ip("1.2.3.4", 4), "1.2.3.4")
        self.assertTrue(common.canonicalise_ip("1.2.3", 4), "1.2.3.0")

        self.assertTrue(common.canonicalise_ip("2001::0:1", 6), "2001::1")
        self.assertTrue(common.canonicalise_ip("abcd:eff::", 6), "abcd:eff::")
        self.assertTrue(common.canonicalise_ip("abcd:0000:eff::", 6),
                        "abcd:0:eff::")
        self.assertTrue(common.canonicalise_ip("::", 6), "::")

