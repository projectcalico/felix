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
felix.test.test_actor
~~~~~~~~~~~~~~~~~~~~~

Tests of the Actor framework.
"""

import logging
import itertools
from gevent.event import AsyncResult

import mock

from calico.felix.actor import actor_event, ResultOrExc, SplitBatchAndRetry
from calico.felix.test.base import BaseTestCase
from calico.felix import actor

# Logger
log = logging.getLogger(__name__)


# noinspection PyUnresolvedReferences
class TestActor(BaseTestCase):
    def setUp(self):
        super(TestActor, self).setUp()
        self._actor = ActorForTesting()
        mock.patch.object(self._actor, "_start_msg_batch",
                          wraps=self._actor._start_msg_batch).start()
        mock.patch.object(self._actor, "_finish_msg_batch",
                          wraps=self._actor._finish_msg_batch).start()

    def run_actor_loop(self):
        self._actor._step()

    @mock.patch("gevent.Greenlet.start", autospec=True)
    def test_start(self, m_start):
        """
        Tests statting the actor starts its greenlet.
        """
        actor = self._actor.start()
        m_start.assert_called_once_with(self._actor.greenlet)
        self.assertEqual(actor, self._actor)

    def test_single_msg(self):
        """
        Tests a batch with one message in it is correctly processed
        on the queue with start/finish batch wrapped around it.
        """
        self._actor.do_a(async=True)
        # Nothing should happen since it should be queued.
        self.assertEqual(self._actor.actions, [])
        self.run_actor_loop()
        # Then we should get a start, batch of only a and a finish.
        self.assertEqual(self._actor.actions, ["sb", "a", "fb"])

    def test_batch(self):
        """
        Tests a batch with multiple messages in it is correctly processed
        on the queue with start/finish batch wrapped around it.
        """
        self._actor.do_a(async=True)
        self._actor.do_a(async=True)
        self._actor.do_b(async=True)
        self._actor.do_a(async=True)
        # Nothing should happen since it should be queued.
        self.assertEqual(self._actor.actions, [])
        self.run_actor_loop()
        # Then we should get a start, batch of only a and a finish.
        self.assertEqual(self._actor.actions, ["sb", "a", "a", "b", "a", "fb"])

    def test_exception(self):
        """
        Tests an exception raised by an event method is returned to the
        correct AsyncResult.
        """
        f_a = self._actor.do_a(async=True)
        f_exc = self._actor.do_exc(async=True)
        f_b = self._actor.do_b(async=True)
        self.run_actor_loop()
        self.assertTrue(f_a.ready())
        self.assertTrue(f_exc.ready())
        self.assertTrue(f_b.ready())
        self.assertEqual("a", f_a.get())
        self.assertEqual("b", f_b.get())
        self.assertRaises(ExpectedException, f_exc.get)
        self.assertRaises(ExpectedException, actor.wait_and_check,
                          [f_a, f_b, f_exc])
        self.assertEqual(self._actor.actions, ["sb", "a", "exc", "b", "fb"])
        self._actor._finish_msg_batch.assert_called_once_with(mock.ANY, [
            ResultOrExc(result='a', exception=None),
            ResultOrExc(result=None, exception=EXPECTED_EXCEPTION),
            ResultOrExc(result='b', exception=None),
        ])

    def test_split_batch(self):
        """
        Tests an exception raised by an event method is returned to the
        correct AsyncResult.
        """
        f_a1 = self._actor.do_a(async=True)
        f_b1 = self._actor.do_b(async=True)
        f_a2 = self._actor.do_a(async=True)
        f_b2 = self._actor.do_b(async=True)
        f_a3 = self._actor.do_a(async=True)
        # Should see these batches:
        # Odd number:
        # [a, b, a, b, a] -> Split
        # [a, b] PENDING: [a, b, a] -> Split
        # Optimization: [b] gets pushed on front of pending batch.
        # [a] PENDING: [b, a, b, a] -> OK
        # Even number:
        # [b, a, b, a] -> Split
        # [b, a] PENDING: [b, a] -> OK
        # [b, a] -> OK
        self._actor._finish_side_effects = iter([
            SplitBatchAndRetry(),
            SplitBatchAndRetry(),
            None,
            SplitBatchAndRetry(),
            None,
            None,
        ])
        self.run_actor_loop()
        self.assertEqual(self._actor.batches, [
            ["sb", "a", "b", "a" ,"b", "a", "fb"],
            ["sb", "a", "b", "fb"],
            ["sb", "a", "fb"],
            ["sb", "b", "a", "b", "a", "fb"],
            ["sb", "b", "a", "fb"],
            ["sb", "b", "a", "fb"],
        ])

    def test_split_batch_exc(self):
        f_a = self._actor.do_a(async=True)
        f_exc = self._actor.do_exc(async=True)
        self._actor._finish_side_effects = iter([
            FinishException()
        ])
        self.run_actor_loop()
        # Gets reported to all callers, which is a bit ugly but something has
        # gone very wrong if we're not dealing with failures in _finish.
        self.assertTrue(f_a.ready())
        self.assertTrue(f_exc.ready())
        self.assertRaises(FinishException, f_a.get)
        self.assertRaises(FinishException, f_exc.get)


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


class RefMgrForTesting(actor.ReferenceManager):
    def _create(self, object_id):
        return ActorForTesting()

    def _on_object_activated(self, object_id, obj):
        obj.active = True


class ActorForTesting(actor.Actor):
    def __init__(self):
        super(ActorForTesting, self).__init__()
        self.actions = []
        self._batch_actions = []
        self.batches = []
        self._finish_side_effects = (lambda _: None for _ in itertools.count())
        self.unreferenced = False
        self.on_unref_result = mock.Mock(autospec=AsyncResult)
        self.started = False

    def start(self):
        self.started = True
        return super(ActorForTesting, self).start()

    @actor_event
    def do_a(self):
        self._batch_actions.append("a")
        assert self._current_msg_name == "do_a"
        return "a"

    @actor_event
    def do_b(self):
        self._batch_actions.append("b")
        assert self._current_msg_name == "do_b"
        return "b"

    @actor_event
    def do_exc(self):
        self._batch_actions.append("exc")
        raise EXPECTED_EXCEPTION

    def _start_msg_batch(self, batch):
        batch = super(ActorForTesting, self)._start_msg_batch(batch)
        self._batch_actions = []
        self._batch_actions.append("sb")
        return batch

    def _finish_msg_batch(self, batch, results):
        super(ActorForTesting, self)._finish_msg_batch(batch, results)
        assert self._current_msg_name is None
        self._batch_actions.append("fb")
        self.actions.extend(self._batch_actions)
        self.batches.append(list(self._batch_actions))
        self._batch_actions = []
        result = next(self._finish_side_effects)
        if isinstance(result, Exception):
            raise result

    # Note: this would mnormally be an actor_event but we bypass that and
    # return our own future.
    def on_unreferenced(self, async=None):
        assert not self.unreferenced
        self.unreferenced = True
        return self.on_unref_result


class ExpectedException(Exception):
    pass


class FinishException(Exception):
    pass


EXPECTED_EXCEPTION = ExpectedException()