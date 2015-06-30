# Copyright (c) Metaswitch Networks 2015. All rights reserved.
import json

import logging
import socket
import gevent
from etcd import EtcdException
from mock import Mock, call, patch
from calico.datamodel_v1 import key_for_status
from calico.felix.fetcd import EtcdAPI,  _EtcdWatcher, ResyncRequired
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
        self.m_config.HEARTBEAT_INTERVAL_SECS = 0
        self.m_config.HEARTBEAT_TTL_SECS = 0

    @patch('calico.felix.fetcd._EtcdWatcher')
    @patch('calico.felix.fetcd.etcd')
    def finish_setup(self, etcd, _EtcdWatcher, **kwargs):
        # Set configuration attributes and start etcd_api
        for key, value in kwargs.iteritems():
            setattr(self.m_config, key, value)
        self.etcd_api = EtcdAPI(self.m_config)

    def test_update_felix_status_disabled(self):
        """
        Test heartbeating is disabled for heartbeat interval 0
        """
        self.finish_setup()
        gevent.sleep(1)
        self.assertFalse(self.etcd_api.client.write.called)

    def test_update_felix_status_single(self):
        """
        Test felix status is updated
        """
        self.finish_setup(HEARTBEAT_INTERVAL_SECS=15,
                          HEARTBEAT_TTL_SECS=37)

        hostname = self.etcd_api._config.HOSTNAME
        key = key_for_status(hostname)
        ttl = self.etcd_api._config.HEARTBEAT_TTL_SECS

        gevent.sleep(1)
        self.etcd_api.client.write.assert_called_with(key, SameTime(), ttl=ttl)

    def test_update_felix_status_continuous(self):
        """
        Test felix status is being continuously updated
        """
        self.finish_setup(HEARTBEAT_INTERVAL_SECS=3,
                          HEARTBEAT_TTL_SECS=10)
        hostname = self.etcd_api._config.HOSTNAME
        key = key_for_status(hostname)
        ttl = self.etcd_api._config.HEARTBEAT_TTL_SECS

        gevent.sleep(50)
        self.etcd_api.client.write.assert_has_calls(15 * [call(key, SameTime(), ttl=ttl)])

    @patch('calico.felix.fetcd.EtcdAPI._on_worker_died')
    def test_update_felix_status_dies_on_exception(self, _on_worker_died):
        """
        Test felix status handles exceptions
        """
        self.finish_setup(HEARTBEAT_INTERVAL_SECS=4,
                          HEARTBEAT_TTL_SECS=12)
        self.etcd_api.client.write = Mock(side_effect = EtcdException)
        gevent.sleep(1)

        self.etcd_api._on_worker_died.assert_called_once()

        self.etcd_api.client.write = Mock()



class SameTime(object):
    # Used to check whether timestamp format is correct (i.e. ISO 8601 Zulu)
    def __eq__(self, other):
        import re
        format_match = re.compile('\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z').match(str(other)) is not None
        return format_match
