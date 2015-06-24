# Copyright (c) Metaswitch Networks 2015. All rights reserved.
import json

import logging
import socket
from etcd import EtcdResult
from mock import Mock, call
from calico.datamodel_v1 import key_for_status
from calico.felix.fetcd import EtcdAPI,  _EtcdWatcher
from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)


class TestEtcdAPI(BaseTestCase):

    def setUp(self):
        super(TestExcdWatcher, self).setUp()
        m_config = Mock()
        m_config.IFACE_PREFIX = "tap"
        m_config.HEARTBEATER_INTERVAL_SECS = 1
        m_config.HEARTBEATER_TTL_SECS = 3

        # expect etcd to be called, make it mock
        # expect watcher to be created, make it mock

        self.etcd_api = EtcdAPI(m_config)

        