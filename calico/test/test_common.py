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
        pass

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

    def test_validate_ipv4_addr(self):
        self.assertTrue(common.validate_ipv4_addr("1.2.3.4"))
        self.assertFalse(common.validate_ipv4_addr("1.2.3.4.5"))
        self.assertFalse(common.validate_ipv4_addr("1.2.3.4/32"))
        self.assertTrue(common.validate_ipv4_addr("1.2.3"))
        self.assertFalse(common.validate_ipv4_addr("bloop"))
        self.assertFalse(common.validate_ipv4_addr("2001::abc"))
        self.assertFalse(common.validate_ipv4_addr("2001::a/64"))

    def test_validate_ipv6_addr(self):
        self.assertFalse(common.validate_ipv6_addr("1.2.3.4"))
        self.assertFalse(common.validate_ipv6_addr("1.2.3.4.5"))
        self.assertFalse(common.validate_ipv6_addr("1.2.3.4/32"))
        self.assertFalse(common.validate_ipv6_addr("1.2.3"))
        self.assertFalse(common.validate_ipv6_addr("bloop"))
        self.assertTrue(common.validate_ipv6_addr("2001::abc"))
        self.assertFalse(common.validate_ipv6_addr("2001::a/64"))
