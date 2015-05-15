# Copyright (c) Metaswitch Networks 2015. All rights reserved.
import json

import logging
import types
from etcd import EtcdResult
from mock import Mock, patch, call
from calico.datamodel_v1 import EndpointId
from calico.felix.fetcd import PathDispatcher, EtcdWatcher, ResyncRequired
from calico.felix.splitter import UpdateSplitter
from calico.felix.test.base import BaseTestCase

_log = logging.getLogger(__name__)


SAME_AS_KEY = object()

VALID_ENDPOINT = {
    "state": "active",
    "name": "tap1234",
    "mac": "aa:bb:cc:dd:ee:ff",
    "profile_id": "prof1",
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


class TestExcdWatcher(BaseTestCase):

    def setUp(self):
        super(TestExcdWatcher, self).setUp()
        m_config = Mock()
        m_config.IFACE_PREFIX = "tap"
        self.watcher = EtcdWatcher(m_config)
        self.m_splitter = Mock(spec=UpdateSplitter)
        self.watcher.splitter = self.m_splitter

    def test_ready_flag_set(self):
        self.dispatch("/calico/v1/Ready", "set", value="true")
        with self.assertRaises(ResyncRequired):
            self.dispatch("/calico/v1/Ready", "set", value="false")
        with self.assertRaises(ResyncRequired):
            self.dispatch("/calico/v1/Ready", "set", value="foo")

    def test_endpoint_set(self):
        self.dispatch("/calico/v1/host/h1/workload/o1/w1/endpoint/e1",
                      "set", value=ENDPOINT_STR)
        self.m_splitter.on_endpoint_update.assert_called_once_with(
            EndpointId("h1", "o1", "w1", "e1"),
            VALID_ENDPOINT,
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
        self.m_splitter.on_rules_update("prof1", RULES, async=True)

    def test_tags_set(self):
        self.dispatch("/calico/v1/policy/profile/prof1/tags", "set",
                      value=TAGS_STR)
        self.m_splitter.on_tags_update("prof1", TAGS, async=True)

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
                    "/calico/v1/Ready",]:
            with self.assertRaises(ResyncRequired):
                self.dispatch(key, "delete")

    def test_per_profile_del(self):
        """
        Test profile deletion triggers dleetion for tags and rules.
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

    def dispatch(self, key, action, value=None):
        """
        Send an EtcdResult to the watcher's dispatcher.
        """
        m_response = Mock(spec=EtcdResult)
        m_response.key = key
        m_response.action = action
        m_response.value = value
        self.watcher.dispatcher.handle_event(m_response)


class _TestPathDispatcherBase(BaseTestCase):
    """
    Abstract base class for Dispatcher tests.
    """
    # Etcd action that this class tests.
    action = None
    # Expected handler type, "set" or "delete".
    expected_handlers = None

    def setUp(self):
        super(_TestPathDispatcherBase, self).setUp()
        self.dispatcher = PathDispatcher()
        self.handlers = {
            "delete": {},
            "set": {},
        }
        self.register("/")
        self.register("/a")
        self.register("/a/<b>")
        self.register("/a/<b>/c")
        self.register("/a/<b>/d")
        self.register("/a/<b>/d/<e>")

    def register(self, key):
        m_on_set = Mock()
        m_on_del = Mock()
        self.dispatcher.register(key, on_set=m_on_set, on_del=m_on_del)
        self.handlers["set"][key.strip("/")] = m_on_set
        self.handlers["delete"][key.strip("/")] = m_on_del

    def assert_handled(self, key, exp_handler=SAME_AS_KEY, **exp_captures):
        if exp_handler is SAME_AS_KEY:
            exp_handler = key
        if exp_handler is not None:
            exp_handler = exp_handler.strip("/")
        m_response = Mock(spec=EtcdResult)
        m_response.key = key
        m_response.action = self.action
        self.dispatcher.handle_event(m_response)
        exp_handlers = self.handlers[self.expected_handlers]
        for handler_key, handler in exp_handlers.iteritems():
            if handler_key == exp_handler:
                continue
            self.assertFalse(handler.called,
                             "Unexpected set handler %s was called for "
                             "key %s" % (handler_key, key))
        unexp_handlers = self.handlers[self.unexpected_handlers]
        for handler_key, handler in unexp_handlers.iteritems():
            self.assertFalse(handler.called,
                             "Unexpected del handler %s was called for "
                             "key %s" % (handler_key, key))
        if exp_handler is not None:
            exp_handlers[exp_handler].assert_called_once_with(
                m_response, **exp_captures)

    @property
    def unexpected_handlers(self):
        if self.expected_handlers == "set":
            return "delete"
        else:
            return "set"

    def test_dispatch_root(self):
        self.assert_handled("/")

    def test_dispatch_no_captures(self):
        self.assert_handled("/a")

    def test_dispatch_capture(self):
        self.assert_handled("/a/bval", exp_handler="/a/<b>", b="bval")

    def test_dispatch_after_capture(self):
        self.assert_handled("/a/bval/c", exp_handler="/a/<b>/c", b="bval")

    def test_dispatch_after_capture_2(self):
        self.assert_handled("/a/bval/d", exp_handler="/a/<b>/d", b="bval")

    def test_multi_capture(self):
        self.assert_handled("/a/bval/d/eval",
                            exp_handler="/a/<b>/d/<e>",
                            b="bval", e="eval")

    def test_non_match(self):
        self.assert_handled("/a/bval/c/eval", exp_handler=None)
        self.assert_handled("/foo", exp_handler=None)

    def test_cover_no_match(self):
        m_result = Mock(spec=EtcdResult)
        m_result.key = "/a"
        m_result.action = "unknown"
        self.dispatcher.handle_event(m_result)
        for handlers in self.handlers.itervalues():
            for key, handler in handlers.iteritems():
                self.assertFalse(handler.called,
                                 msg="Unexpected handler called: %s" % key)


class TestDispatcherSet(_TestPathDispatcherBase):
    action = "set"
    expected_handlers = "set"


class TestDispatcherCaS(_TestPathDispatcherBase):
    action = "compareAndSwap"
    expected_handlers = "set"


class TestDispatcherCreate(_TestPathDispatcherBase):
    action = "create"
    expected_handlers = "set"


class TestDispatcherUpdate(_TestPathDispatcherBase):
    action = "update"
    expected_handlers = "set"


class TestDispatcherDel(_TestPathDispatcherBase):
    action = "delete"
    expected_handlers = "delete"


class TestDispatcherCaD(_TestPathDispatcherBase):
    action = "compareAndDelete"
    expected_handlers = "delete"


class TestDispatcherExpire(_TestPathDispatcherBase):
    action = "expire"
    expected_handlers = "delete"
