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
felix.test.test_felix
~~~~~~~~~~~

Top level tests for Felix.
"""
import logging
import mock
import sys
import time
import unittest

import calico.felix.test.stub_etcd as stub_etcd
sys.modules['etcd'] = stub_etcd

import calico.felix.futils as futils
import calico.felix.felix as felix

# Logger
log = logging.getLogger(__name__)

class TestBasic(unittest.TestCase):
    def test_nothing(self):
        pass
