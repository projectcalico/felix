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
felix.test.test_etcd_api
~~~~~~~~~~~

Top level tests for EtcdAPI.
"""
import logging
import socket
import gevent
from etcd import EtcdException
from mock import Mock, call, patch
from calico.datamodel_v1 import key_for_status, key_for_uptime
from calico.felix.fetcd import EtcdAPI
from calico.felix.test.base import BaseTestCase


_log = logging.getLogger(__name__)

# To make testing continuous status reporting more convenient,
# we speed up sleeping.
_oldsleep = gevent.sleep
def _newsleep(duration):
    _oldsleep(duration * 0.01)
gevent.sleep = _newsleep


class TestEtcdAPI(BaseTestCase):
    def setUp(self):
        super(TestEtcdAPI, self).setUp()
        self.m_config = Mock()
        self.m_config.IFACE_PREFIX = "tap"
        self.m_config.ETCD_ADDR = "localhost:4001"
        self.m_config.HOSTNAME = socket.gethostname()
        self.m_config.RESYNC_INTERVAL = 0
        self.m_config.REPORTING_INTERVAL_SECS = 0
        self.m_config.REPORTING_TTL_SECS = 0

    @patch('calico.felix.fetcd.EtcdAPI.write_to_etcd')
    @patch('calico.felix.fetcd._EtcdWatcher')
    @patch('calico.felix.fetcd.etcd')
    def finish_setup(self, m_etcd, m_EtcdWatcher, m_write_to_etcd, **kwargs):
        # Set configuration attributes and start etcd_api
        for key, value in kwargs.iteritems():
            setattr(self.m_config, key, value)

        self.m_hosts_ipset = Mock()
        self.etcd_api = EtcdAPI(self.m_config, self.m_hosts_ipset)

        self.etcd_api.write_to_etcd = Mock()

    def run_actor_loop(self):
        self.etcd_api._step()

    def test_write_to_etcd_actor_message(self):
        """
        Test write_to_etcd actor message calls client.write
        """
        self.m_hosts_ipset = Mock()
        self.etcd_api = EtcdAPI(self.m_config, self.m_hosts_ipset)

        with patch.object(self.etcd_api.client, 'write'):
            self.etcd_api.write_to_etcd('key', 'value', async=True)
            self.run_actor_loop()
            self.assertTrue(self.etcd_api.client.write.called)

    def test_update_felix_status_disabled(self):
        """
        Test reporting is disabled for reporting interval 0
        """
        self.finish_setup()
        gevent.sleep(1)
        self.assertFalse(self.etcd_api.write_to_etcd.called)

    def test_update_felix_status_single(self):
        """
        Test felix status is updated
        """
        self.finish_setup(REPORTING_INTERVAL_SECS=15,
                          REPORTING_TTL_SECS=37)

        hostname = self.etcd_api._config.HOSTNAME
        status_key = key_for_status(hostname)
        uptime_key = key_for_uptime(hostname)

        ttl = self.etcd_api._config.REPORTING_TTL_SECS

        gevent.sleep(1)

        status_call = call(status_key, TestIfStatus(), async=True)
        uptime_call = call(uptime_key, TestIfUptime(), ttl=ttl, async=True)
        self.etcd_api.write_to_etcd.assert_has_calls([status_call,
                                                      uptime_call])

    def test_update_felix_status_continuous(self):
        """
        Test felix status is being continuously updated
        """
        self.finish_setup(REPORTING_INTERVAL_SECS=3,
                          REPORTING_TTL_SECS=10)
        hostname = self.etcd_api._config.HOSTNAME
        status_key = key_for_status(hostname)
        uptime_key = key_for_uptime(hostname)
        ttl = self.etcd_api._config.REPORTING_TTL_SECS

        gevent.sleep(50)

        status_call = call(status_key, TestIfStatus(), async=True)
        uptime_call = call(uptime_key, TestIfUptime(), ttl=ttl, async=True)
        self.etcd_api.write_to_etcd.assert_has_calls(16 * [status_call,
                                                           uptime_call])

    @patch('calico.felix.fetcd._reconnect')
    def test_update_felix_status_reconnects_on_etcd_exception(self, _reconnect):
        """
        Test felix status handles exceptions
        """
        self.finish_setup(REPORTING_INTERVAL_SECS=4,
                          REPORTING_TTL_SECS=12)
        self.etcd_api.write_to_etcd = Mock(side_effect=EtcdException)

        gevent.sleep(1)

        self.assertTrue(_reconnect.called)


class TestIfStatus(object):
    """
    Used to check whether status has expected format
    i.e. whether timestamp is in ISO 8601 Zulu format
    """
    def __eq__(self, other):
        import re
        timestamp_regex = re.compile('.*"status_time": "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?".*')
        is_timestamp =  timestamp_regex.match(str(other)) is not None
        return is_timestamp
    def __repr__(self):
        return '%s()' % self.__class__.__name__

class TestIfUptime(object):
    """
    Used to check whether uptime has correct format (i.e. whether it is
    non-negative integer)
    """
    def __eq__(self, other):
        is_int = type(other) == int
        is_non_negative = other >= 0
        return is_int and is_non_negative
    def __repr__(self):
        return '%s()' % self.__class__.__name__
