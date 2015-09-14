# Copyright (c) Metaswitch Networks 2015. All rights reserved.
import datetime
import json
import logging
from etcd import EtcdResult, EtcdException
import etcd
from gevent.event import Event
import gevent
from mock import Mock, call, patch, ANY
import socket

from calico.datamodel_v1 import EndpointId, key_for_status, \
    key_for_uptime
from calico.felix.config import Config
from calico.felix.ipsets import IpsetActor
from calico.felix.fetcd import _EtcdWatcher, ResyncRequired, EtcdAPI, \
    die_and_restart
from calico.felix.splitter import UpdateSplitter
from calico.felix.test.base import BaseTestCase


_log = logging.getLogger(__name__)


VALID_ENDPOINT = {
    "state": "active",
    "name": "tap1234",
    "mac": "aa:bb:cc:dd:ee:ff",
    "profile_ids": ["prof1"],
    "ipv4_nets": [
        "10.0.0.1/32",
    ],
    "ipv6_nets": [
        "dead::beef/128"
    ]
}
ENDPOINT_STR = json.dumps(VALID_ENDPOINT)

RULES = {
    "inbound_rules": [],
    "outbound_rules": [],
}
RULES_STR = json.dumps(RULES)

TAGS = ["a", "b"]
TAGS_STR = json.dumps(TAGS)

ETCD_ADDRESS = 'localhost:4001'

class TestEtcdAPI(BaseTestCase):

    @patch("calico.felix.fetcd._EtcdWatcher", autospec=True)
    @patch("gevent.spawn", autospec=True)
    def test_create(self, m_spawn, m_etcd_watcher):
        m_config = Mock(spec=Config)
        m_config.ETCD_ADDR = ETCD_ADDRESS
        m_hosts_ipset = Mock(spec=IpsetActor)
        api = EtcdAPI(m_config, m_hosts_ipset)
        m_etcd_watcher.assert_has_calls([
            call(m_config, m_hosts_ipset).link(api._on_worker_died),
            call(m_config, m_hosts_ipset).start(),
        ])
        m_spawn.assert_has_calls([
            call(api._periodically_resync),
            call(api._periodically_resync).link_exception(api._on_worker_died)
        ])

    @patch("calico.felix.fetcd._EtcdWatcher", autospec=True)
    @patch("gevent.spawn", autospec=True)
    @patch("gevent.sleep", autospec=True)
    def test_periodic_resync_mainline(self, m_sleep, m_spawn, m_etcd_watcher):
        m_configured = Mock(spec=Event)
        m_etcd_watcher.return_value.configured = m_configured
        m_config = Mock(spec=Config)
        m_config.ETCD_ADDR = ETCD_ADDRESS
        m_hosts_ipset = Mock(spec=IpsetActor)
        api = EtcdAPI(m_config, m_hosts_ipset)
        m_config.RESYNC_INTERVAL = 10
        with patch.object(api, "force_resync") as m_force_resync:
            m_force_resync.side_effect = ExpectedException()
            self.assertRaises(ExpectedException, api._periodically_resync)
        m_configured.wait.assert_called_once_with()
        m_sleep.assert_called_once_with(ANY)
        sleep_time = m_sleep.call_args[0][0]
        self.assertTrue(sleep_time >= 10)
        self.assertTrue(sleep_time <= 12)

    @patch("calico.felix.fetcd._EtcdWatcher", autospec=True)
    @patch("gevent.spawn", autospec=True)
    @patch("gevent.sleep", autospec=True)
    def test_periodic_resync_disabled(self, m_sleep, m_spawn, m_etcd_watcher):
        m_etcd_watcher.return_value.configured = Mock(spec=Event)
        m_config = Mock(spec=Config)
        m_config.ETCD_ADDR = ETCD_ADDRESS
        m_hosts_ipset = Mock(spec=IpsetActor)
        api = EtcdAPI(m_config, m_hosts_ipset)
        m_config.RESYNC_INTERVAL = 0
        with patch.object(api, "force_resync") as m_force_resync:
            m_force_resync.side_effect = Exception()
            api._periodically_resync()

    @patch("calico.felix.fetcd._EtcdWatcher", autospec=True)
    @patch("gevent.spawn", autospec=True)
    def test_force_resync(self, m_spawn, m_etcd_watcher):
        m_config = Mock(spec=Config)
        m_config.ETCD_ADDR = ETCD_ADDRESS
        m_hosts_ipset = Mock(spec=IpsetActor)
        api = EtcdAPI(m_config, m_hosts_ipset)
        api.force_resync(async=True)
        self.step_actor(api)
        self.assertTrue(m_etcd_watcher.return_value.resync_after_current_poll)


class ExpectedException(Exception):
    pass


class TestExcdWatcher(BaseTestCase):

    def setUp(self):
        super(TestExcdWatcher, self).setUp()
        self.m_config = Mock()
        self.m_config.HOSTNAME = "hostname"
        self.m_config.IFACE_PREFIX = "tap"
        self.m_config.ETCD_ADDR = ETCD_ADDRESS
        self.m_hosts_ipset = Mock(spec=IpsetActor)
        self.watcher = _EtcdWatcher(self.m_config, self.m_hosts_ipset)
        self.m_splitter = Mock(spec=UpdateSplitter)
        self.watcher.splitter = self.m_splitter
        self.client = Mock(spec=etcd.Client)
        self.watcher.client = self.client

    @patch("gevent.sleep", autospec=True)
    @patch("calico.felix.fetcd._build_config_dict", autospec=True)
    @patch("calico.felix.fetcd.die_and_restart", autospec=True)
    def test_load_config(self, m_die, m_build_dict, m_sleep):
        # First call, loads the config.
        global_cfg = {"foo": "bar"}
        m_build_dict.side_effect = iter([
            # First call, global-only.
            global_cfg,
            # Second call, no change.
            global_cfg,
            # Third call, change of config.
            {"foo": "baz"}, {"biff": "bop"}])
        self.client.read.side_effect = iter([
            # First time round the loop, fail to read global config, should
            # retry.
            etcd.EtcdKeyNotFound,
            # Then get the global config but there's not host-only config.
            None, etcd.EtcdKeyNotFound,
            # Twice...
            None, etcd.EtcdKeyNotFound,
            # Then some host-only config shows up.
            None, None])

        # First call.
        self.watcher._load_config()

        m_sleep.assert_called_once_with(5)
        self.assertFalse(m_die.called)

        m_report = self.m_config.report_etcd_config
        rpd_host_cfg, rpd_global_cfg = m_report.mock_calls[0][1]
        self.assertEqual(rpd_host_cfg, {})
        self.assertEqual(rpd_global_cfg, global_cfg)
        self.assertTrue(rpd_host_cfg is not self.watcher.last_host_config)
        self.assertTrue(rpd_global_cfg is not self.watcher.last_global_config)
        self.assertEqual(rpd_host_cfg, self.watcher.last_host_config)
        self.assertEqual(rpd_global_cfg, self.watcher.last_global_config)

        self.assertEqual(self.watcher.last_host_config, {})
        self.assertEqual(self.watcher.last_global_config, global_cfg)
        self.watcher.configured.set()  # Normally done by the caller.
        self.client.read.assert_has_calls([
            call("/calico/v1/config", recursive=True),
            call("/calico/v1/host/hostname/config", recursive=True),
        ])

        # Second call, no change.
        self.watcher._load_config()
        self.assertFalse(m_die.called)

        # Third call, should detect the config change and die.
        self.watcher._load_config()
        m_die.assert_called_once_with()

    def test_resync_flag(self):
        self.watcher.resync_after_current_poll = True
        self.assertRaises(ResyncRequired, self.watcher._wait_for_etcd_event)
        self.assertFalse(self.watcher.resync_after_current_poll)

    def test_ready_flag_set(self):
        self.dispatch("/calico/v1/Ready", "set", value="true")
        self.assertRaises(ResyncRequired, self.dispatch,
                          "/calico/v1/Ready", "set", value="false")
        self.assertRaises(ResyncRequired, self.dispatch,
                          "/calico/v1/Ready", "set", value="foo")

    def test_endpoint_set(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value=ENDPOINT_STR)
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            EndpointId("h1", "o1", "w1", "e1"),
            VALID_ENDPOINT,
            async=True,
        )

    def test_endpoint_set_bad_json(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value="{")
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            EndpointId("h1", "o1", "w1", "e1"),
            None,
            async=True,
        )

    def test_endpoint_set_invalid(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value="{}")
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            EndpointId("h1", "o1", "w1", "e1"),
            None,
            async=True,
        )

    def test_parent_dir_delete(self):
        """
        Test that deletions of parent directories of endpoints are
        correctly handled.
        """
        # This additional  endpoint should be ignored by the deletes below.
        self.dispatch("/calico/v1/host/h2/workload/o1/w2/endpoint/e2",
                      "set", value=ENDPOINT_STR)
        for path in ["/calico/v1/host/h1",
                     "/calico/v1/host/h1/workload",
                     "/calico/v1/host/h1/workload/o1",
                     "/calico/v1/host/h1/workload/o1/w1",
                     "/calico/v1/host/h1/workload/o1/w1/endpoint"]:
            # Create endpoints in the cache.
            self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                          "set", value=ENDPOINT_STR)
            self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e2",
                          "set", value=ENDPOINT_STR)
            # This endpoint should not get cleaned up if only workload w1 is
            # deleted...
            self.dispatch("/calico/v1/host/h1/workload/o1/w3/endpoint/e3",
                          "set", value=ENDPOINT_STR)

            self.assertEqual(self.watcher.endpoint_ids_per_host, {
                "h1": set([EndpointId("h1", "o1", "w1", "e1"),
                           EndpointId("h1", "o1", "w1", "e2"),
                           EndpointId("h1", "o1", "w3", "e3")]),
                "h2": set([EndpointId("h2", "o1", "w2", "e2")]),
            })
            self.m_splitter.on_endpoint_update.reset_mock()
            # Delete one of its parent dirs, should delete the endpoint.
            self.dispatch(path, "delete")
            exp_calls = [
                call(EndpointId("h1", "o1", "w1", "e1"), None, async=True),
                call(EndpointId("h1", "o1", "w1", "e2"), None, async=True),
            ]
            if path < "/calico/v1/host/h1/workload/o1/w1":
                # Should also delete workload w3.
                exp_calls.append(call(EndpointId("h1", "o1", "w3", "e3"),
                                      None, async=True))
            self.m_splitter.on_endpoint_update.assert_has_calls(exp_calls,
                                                                any_order=True)
            # Cache should be cleaned up.
            exp_cache = {"h2": set([EndpointId("h2", "o1", "w2", "e2")])}
            if path >= "/calico/v1/host/h1/workload/o1/w1":
                # Should not have deleted workload w3.  Add it in.
                exp_cache["h1"] = set([EndpointId("h1", "o1", "w3", "e3")])
            self.assertEqual(self.watcher.endpoint_ids_per_host, exp_cache)

            # Then simulate another delete, should have no effect.
            self.m_splitter.on_endpoint_update.reset_mock()
            self.dispatch(path, "delete")
            self.assertFalse(self.m_splitter.on_endpoint_update.called)

    def test_rules_set(self):
        self.dispatch("/calico/v1/policy/profile/prof1/rules", "set",
                      value=RULES_STR)
        self.m_splitter.on_rules_update.assert_called_once_with("prof1",
                                                                RULES,
                                                                async=True)

    def test_rules_set_bad_json(self):
        self.dispatch("/calico/v1/policy/profile/prof1/rules", "set",
                      value="{")
        self.m_splitter.on_rules_update.assert_called_once_with("prof1",
                                                                None,
                                                                async=True)

    def test_rules_set_invalid(self):
        self.dispatch("/calico/v1/policy/profile/prof1/rules", "set",
                      value='{}')
        self.m_splitter.on_rules_update.assert_called_once_with("prof1",
                                                                None,
                                                                async=True)

    def test_tags_set(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value=TAGS_STR)
        self.m_splitter.on_tags_update.assert_called_once_with("prof1",
                                                               TAGS,
                                                               async=True)

    def test_tags_set_bad_json(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value="{")
        self.m_splitter.on_tags_update.assert_called_once_with("prof1",
                                                               None,
                                                               async=True)

    def test_tags_set_invalid(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value="[{}]")
        self.m_splitter.on_tags_update.assert_called_once_with("prof1",
                                                               None,
                                                               async=True)

    def test_dispatch_delete_resync(self):
        """
        Test dispatcher is correctly configured to trigger resync for
        expected paths.
        """
        for key in ["/calico/v1",
                    "/calico/v1/host",
                    "/calico/v1/policy",
                    "/calico/v1/policy/profile",
                    "/calico/v1/config",
                    "/calico/v1/config/Foo",
                    "/calico/v1/Ready",]:
            self.assertRaises(ResyncRequired, self.dispatch, key, "delete")

    def test_per_profile_del(self):
        """
        Test profile deletion triggers deletion for tags and rules.
        """
        self.dispatch("/calico/v1/policy/profile/profA", action="delete")
        self.m_splitter.on_tags_update.assert_called_once_with("profA", None,
                                                               async=True)
        self.m_splitter.on_rules_update.assert_called_once_with("profA", None,
                                                                async=True)

    def test_tags_del(self):
        """
        Test tag-only deletion.
        """
        self.dispatch("/calico/v1/policy/profile/profA/tags", action="delete")
        self.m_splitter.on_tags_update.assert_called_once_with("profA", None,
                                                               async=True)
        self.assertFalse(self.m_splitter.on_rules_update.called)

    def test_rules_del(self):
        """
        Test rules-only deletion.
        """
        self.dispatch("/calico/v1/policy/profile/profA/rules", action="delete")
        self.m_splitter.on_rules_update.assert_called_once_with("profA", None,
                                                                async=True)
        self.assertFalse(self.m_splitter.on_tags_update.called)

    def test_endpoint_del(self):
        """
        Test endpoint-only deletion.
        """
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      action="delete")
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            EndpointId("h1", "o1", "w1", "e1"),
            None,
            async=True,
        )

    def test_host_ip_set(self):
        """
        Test set for the IP of a host.
        """
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            ["10.0.0.1"],
            async=True,
        )

    def test_host_ip_ipip_disabled(self):
        """
        Test set for the IP of a host.
        """
        self.m_config.IP_IN_IP_ENABLED = False
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.assertFalse(self.m_hosts_ipset.replace_members.called)
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="delete")
        self.assertFalse(self.m_hosts_ipset.replace_members.called)

    def test_host_ip_del(self):
        """
        Test set for the IP of a host.
        """
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.reset_mock()
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="delete")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            [],
            async=True,
        )

    def test_host_ip_invalid(self):
        """
        Test set for the IP of a host.
        """
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.reset_mock()
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="gibberish")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            [],
            async=True,
        )

    def test_host_del_clears_ip(self):
        """
        Test set for the IP of a host.
        """
        self.dispatch("/calico/v1/host/foo/bird_ip",
                      action="set", value="10.0.0.1")
        self.m_hosts_ipset.reset_mock()
        self.dispatch("/calico/v1/host/foo",
                      action="delete")
        self.m_hosts_ipset.replace_members.assert_called_once_with(
            [],
            async=True,
        )

    def test_config_update_triggers_resync(self):
        self.assertRaises(ResyncRequired, self.dispatch,
                          "/calico/v1/config/Foo", "set", "bar")
        self.assertRaises(ResyncRequired, self.dispatch,
                          "/calico/v1/host/foo/config/Foo", "set", "bar")

    @patch("os._exit", autospec=True)
    @patch("gevent.sleep", autospec=True)
    def test_die_and_restart(self, m_sleep, m_exit):
        die_and_restart()
        m_sleep.assert_called_once_with(2)
        m_exit.assert_called_once_with(1)

    def dispatch(self, key, action, value=None):
        """
        Send an EtcdResult to the watcher's dispatcher.
        """
        m_response = Mock(spec=EtcdResult)
        m_response.key = key
        m_response.action = action
        m_response.value = value
        self.watcher.dispatcher.handle_event(m_response)


class TestEtcdReporting(BaseTestCase):
    def setUp(self):
        super(TestEtcdReporting, self).setUp()
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

    def test_write_to_etcd_actor_message(self):
        """
        Test write_to_etcd actor message calls client.write
        """
        self.m_hosts_ipset = Mock()
        self.etcd_api = EtcdAPI(self.m_config, self.m_hosts_ipset)

        with patch.object(self.etcd_api.client, 'write'):
            self.etcd_api.write_to_etcd('key', 'value', async=True)
            self.step_actor(self.etcd_api)
            self.assertTrue(self.etcd_api.client.write.called)

    def test_update_felix_status_disabled(self):
        """
        Test reporting is disabled for reporting interval 0
        """
        self.finish_setup()
        # We call gevent.sleep so that _status_reporting thread is executed -
        # since no interval and ttl is given, _status_reporting thread returns
        # instead of writing to etcd.
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

        # We call gevent.sleep so that _status_reporting thread is executed
        gevent.sleep(1)

        status_call = call(status_key, TestIfStatus(), async=True)
        uptime_call = call(uptime_key, TestIfUptime(), ttl=ttl, async=True)
        self.etcd_api.write_to_etcd.assert_has_calls([status_call,
                                                      uptime_call])

    def test_update_felix_status_continuous(self):
        """
        Test felix status is being continuously updated
        """
        self.finish_setup(REPORTING_INTERVAL_SECS=5,
                          REPORTING_TTL_SECS=17)
        hostname = self.etcd_api._config.HOSTNAME
        status_key = key_for_status(hostname)
        uptime_key = key_for_uptime(hostname)
        ttl = self.etcd_api._config.REPORTING_TTL_SECS

        status_call = call(status_key, TestIfStatus(), async=True)
        uptime_call = call(uptime_key, TestIfUptime(), ttl=ttl, async=True)

        # We call gevent.sleep so that _status_reporting thread is executed
        gevent.sleep(5)

        last_status_call = None
        for update in range(5):
            gevent.sleep(5)
            # Check that both uptime and status were updated
            self.etcd_api.write_to_etcd.assert_has_calls([status_call, uptime_call])
            # Update last_status_call and reset write_to_etcd calls
            last_status_call = self.etcd_api.write_to_etcd.mock_calls[0]
            self.etcd_api.write_to_etcd.reset_mock()

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
    Used to check whether status has JSON format and contains expected
    attributes, whis are:
    - timestamp in ISO 8601 Zulu format
    """
    def __eq__(self, other):
        try:
            status = json.loads(other)
            time = status['status_time']
            parsed_time = datetime.datetime.strptime(time, "%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, KeyError):
            return False
        return True

    def __repr__(self):
        return '%s()' % self.__class__.__name__

class TestIfUptime(object):
    """
    Used to check whether uptime has correct format (i.e. whether it is
    non-negative integer)
    """
    def __eq__(self, other):
        is_int = (type(other) == int)
        is_non_negative = (other >= 0)
        return is_int and is_non_negative

    def __repr__(self):
        return '%s()' % self.__class__.__name__

def is_json(object):
    """
    Help function, returns whether given object is json.
    """
    try:
        json.loads(object)
    except ValueError:
        return False
    return True
