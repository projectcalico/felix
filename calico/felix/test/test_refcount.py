# Copyright (c) Metaswitch Networks 2015. All rights reserved.

import logging
from calico.felix.refcount import ReferenceManager
from calico.felix.test.base import BaseTestCase
from calico.felix.test.test_actor import ActorForTesting
import mock

_log = logging.getLogger(__name__)


class TestReferenceManager(BaseTestCase):
    def setUp(self):
        super(TestReferenceManager, self).setUp()
        self._rm = RefMgrForTesting()

    def test_multiple_gets_receive_same_obj(self):
        f1 = self._rm.get_and_incref("foo", async=True)
        self._rm._step()
        self.assertTrue(f1.ready())
        f2 = self._rm.get_and_incref("foo", async=True)
        self._rm._step()
        self.assertTrue(f2.ready())
        obj_1 = f1.get()
        obj_2 = f2.get()
        self.assertTrue(obj_1 is obj_2)
        self.assertTrue(isinstance(obj_1, ActorForTesting))

    @mock.patch("gevent.Greenlet.start", autospec=True)
    def test_ref_counting_and_cleanup(self, m_start):
        # Create an actor and watch its refcount go up and down.
        f1 = self._rm.get_and_incref("foo", async=True)
        self._rm._step()
        actor_ref = f1.get_nowait()
        self.assertEqual(self._rm.ref_counts_by_id["foo"], 1)

        f2 = self._rm.get_and_incref("foo", async=True)
        self._rm._step()
        f2.get_nowait()
        self.assertEqual(self._rm.ref_counts_by_id["foo"], 2)

        f3 = self._rm.decref("foo", async=True)
        self._rm._step()
        f3.get_nowait()
        self.assertEqual(self._rm.ref_counts_by_id["foo"], 1)

        f4 = self._rm.decref("foo", async=True)
        self._rm._step()
        f4.get_nowait()
        # To avoid leak, should be deleted from dict, not just 0.
        self.assertFalse("foo" in self._rm.ref_counts_by_id)

        # Should now have a future logged in cleanup_futures until we simulate
        # the Actor's callback.
        self.assertTrue("foo" in self._rm.cleanup_futures)
        self.assertTrue(actor_ref.unreferenced)

        # _on_object_cleanup_complete should be linked to the result.
        callback = actor_ref.on_unref_result.rawlink.call_args[0][0]
        f = callback()
        self.step_actor(self._rm)  # Will fail if the callback didn't work.
        f.get_nowait()
        self.assertTrue("foo" not in self._rm.cleanup_futures)
        self.assertTrue("foo" not in self._rm.ref_counts_by_id)
        self.assertTrue("foo" not in self._rm.objects_by_id)

    @mock.patch("gevent.Greenlet.start", autospec=True)
    def test_recreate_while_cleaning_up(self, m_start):
        """
        Test creating an actor while the previous one for that ID is still
        cleaning itself up.  The new actor should be created as normal but
        its start method should be queued up behind the old one via rawlink.
        """
        # Create an actor...
        f1 = self._rm.get_and_incref("foo", async=True)
        self.step_actor(self._rm)
        actor_ref = f1.get_nowait()
        self.assertTrue(actor_ref.started)  # Should be started immediately.
        # Then decref it....
        f2 = self._rm.decref("foo", async=True)
        self.step_actor(self._rm)
        f2.get_nowait()
        # Then recreate it before we clean up the first one...
        f3 = self._rm.get_and_incref("foo", async=True)
        self.step_actor(self._rm)
        actor_ref_2 = f3.get_nowait()

        # Should get a new actor:
        self.assertFalse(actor_ref is actor_ref_2)
        self.assertEqual(self._rm.ref_counts_by_id["foo"], 1)

        # Should still have a future logged in cleanup_futures:
        self.assertTrue("foo" in self._rm.cleanup_futures)

        # New actor shouldn't be started yet.
        self.assertFalse(actor_ref_2.started)

        # The start for the new actor should be queued behind the cleanup of
        # the old.
        m_rawlink = actor_ref.on_unref_result.rawlink
        cleanup_call, start_call = m_rawlink.call_args_list
        cleanup_partial = cleanup_call[0][0]
        cleanup_partial()
        self.step_actor(self._rm)  # Will fail if the callback didn't work.

        start_fn = start_call[0][0]
        self.assertEqual(start_fn, actor_ref_2.start)
        self.assertTrue("foo" not in self._rm.cleanup_futures)
        self.assertTrue("foo" in self._rm.ref_counts_by_id)
        self.assertTrue("foo" in self._rm.objects_by_id)

    @mock.patch("gevent.Greenlet.start", autospec=True)
    def test_double_recreate_while_cleaning_up(self, m_start):
        """
        Test creating an actor while the previous one for that ID is still
        cleaning itself up.  The new actor should be created as normal but
        its start method should be queued up behind the old one via rawlink.
        """
        # Create an actor...
        f1 = self._rm.get_and_incref("foo", async=True)
        self.step_actor(self._rm)
        actor_1 = f1.get_nowait()
        self.assertTrue(actor_1.started)  # Should be started immediately.

        # Then decref it....
        f2 = self._rm.decref("foo", async=True)
        self.step_actor(self._rm)
        f2.get_nowait()
        # Then recreate it before we clean up the first one...
        f3 = self._rm.get_and_incref("foo", async=True)
        self.step_actor(self._rm)
        actor_2 = f3.get_nowait()

        # Then decref it....
        f4 = self._rm.decref("foo", async=True)
        self.step_actor(self._rm)
        f4.get_nowait()
        # Then recreate it before we clean up the second one...
        f5 = self._rm.get_and_incref("foo", async=True)
        self.step_actor(self._rm)
        actor_3 = f5.get_nowait()

        # Should get a new actor each time:
        self.assertFalse(actor_1 is actor_2)
        self.assertFalse(actor_2 is actor_3)
        self.assertEqual(self._rm.ref_counts_by_id["foo"], 1)

        # Should still have a future logged in cleanup_futures:
        self.assertTrue("foo" in self._rm.cleanup_futures)

        # New actors shouldn't be started yet.
        self.assertFalse(actor_2.started)
        self.assertFalse(actor_3.started)

        # The start for the 2nd actor should be queued behind the cleanup of
        # the second.
        m_rawlink = actor_1.on_unref_result.rawlink
        cleanup_call, start_call = m_rawlink.call_args_list
        cleanup_partial = cleanup_call[0][0]
        cleanup_partial()
        self.step_actor(self._rm)  # Will fail if the callback didn't work.

        # The start for the newest actor should be queued behind the cleanup of
        # the second.
        m_rawlink = actor_2.on_unref_result.rawlink
        cleanup_call, start_call = m_rawlink.call_args_list
        cleanup_partial = cleanup_call[0][0]
        cleanup_partial()
        self.step_actor(self._rm)  # Will fail if the callback didn't work.

        start_fn = start_call[0][0]
        self.assertEqual(start_fn, actor_3.start)
        self.assertTrue("foo" not in self._rm.cleanup_futures)
        self.assertTrue("foo" in self._rm.ref_counts_by_id)
        self.assertTrue("foo" in self._rm.objects_by_id)


class RefMgrForTesting(ReferenceManager):
    def _create(self, object_id):
        return ActorForTesting()

    def _on_object_started(self, object_id, obj):
        obj.active = True