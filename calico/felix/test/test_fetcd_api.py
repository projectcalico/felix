# Copyright (c) Metaswitch Networks 2015. All rights reserved.
import json

import logging
import socket
import gevent
from etcd import EtcdException
from mock import Mock, call, patch
from calico.datamodel_v1 import key_for_status, key_for_uptime
from calico.felix.fetcd import EtcdAPI,  _EtcdWatcher, ResyncRequired, _reconnect
from calico.felix.test.base import BaseTestCase

import gevent
import datetime


# For the purpose of the testing, speed up sleeping
_oldsleep = gevent.sleep
def _newsleep(duration):
               _oldsleep(duration * 0.01)
gevent.sleep = _newsleep

_log = logging.getLogger(__name__)


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
    def finish_setup(self, etcd, _EtcdWatcher, write_to_etcd, **kwargs):
        # Set configuration attributes and start etcd_api
        for key, value in kwargs.iteritems():
            setattr(self.m_config, key, value)
        self.etcd_api = EtcdAPI(self.m_config)
        self.etcd_api.write_to_etcd = Mock()

    def test_write_to_etcd_actor_message(self):
        self.etcd_api = EtcdAPI(self.m_config)
        self.etcd_api.client.write = Mock()
        self.etcd_api.write_to_etcd('key', 'value', async=True)
        self.etcd_api._step()
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

        self.etcd_api.write_to_etcd.assert_has_calls([call(status_key, SameTime(), async=True),
                                                          call(uptime_key, SameTimeDiff(), ttl=ttl, async=True)])

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
        self.etcd_api.write_to_etcd.assert_has_calls(15 * [call(status_key, SameTime(), async=True),
                                                          call(uptime_key, SameTimeDiff(), ttl=ttl, async=True)])

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



class SameTime(object):
    # Used to check whether timestamp format is correct (i.e. ISO 8601 Zulu)
    def __eq__(self, other):
        import re
        format_match = re.compile('\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z').match(str(other)) is not None
        return format_match

class SameTimeDiff(object):
    def __eq__(self, other):
        return type(other)