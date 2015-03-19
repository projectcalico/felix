# -*- coding: utf-8 -*-
# Copyright (c) 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
felix.actor
~~~~~~~~~~~

Actor infrastructure used in Felix.
"""
import logging
import functools
import collections
import weakref
import sys
import traceback

import gevent
import os
from gevent.event import AsyncResult
from gevent.queue import Queue


_log = logging.getLogger(__name__)


DEFAULT_QUEUE_SIZE = 10

ResultOrExc = collections.namedtuple("ResultOrExc", ("result", "exception"))


_refs = {}
_ref_idx = 0

class Message(object):
    """
    Message passed to an actor.
    """
    def __init__(self, method, results, recipient):
        self.method = method
        self.results = results
        self.name = method.func.__name__
        self.recipient = recipient

    def __str__(self):
        data = "%s to %s" % (self.name, self.recipient)
        return data

class ExceptionTrackingRef(weakref.ref):
    """
    Specialised weak reference with a slot to hold an exception
    that was leaked.
    """

    # Note: superclass implements __new__ so we have to mimic its args
    # and have the callback passed in.
    def __init__(self, obj, callback):
        super(ExceptionTrackingRef, self).__init__(obj, callback)
        self.exception = None
        self.tag = None

        # Callback won't get triggered if we die before the object we reference
        # so stash a reference to this object, which we clean up when the
        # TrackedAsyncResult is GCed.
        global _ref_idx
        self.idx = _ref_idx
        _ref_idx += 1
        _refs[self.idx] = self

    def __str__(self):
        return (self.__class__.__name__ + "<%s/%s,exc=%s>" %
                (self.tag, self.idx, self.exception))


def _reap_ref(ref):
    """
    Called when a TrackedAsyncResult gets GCed.

    Looks for leaked exceptions.

    :param ExceptionTrackingRef ref: The ref that may contain a leaked
        exception.
    """
    _log.debug("Reaping %s", ref)
    assert isinstance(ref, ExceptionTrackingRef)
    del _refs[ref.idx]
    if ref.exception:
        _log.critical("TrackedAsyncResult %s was leaked with exception %r",
                      ref.tag, ref.exception)
        print >> sys.stderr, "TrackedAsyncResult %s was leaked with " \
                             "exception %r" % (ref.tag, ref.exception)

        # Called from the GC so we can't raise an exception, just die.
        _exit(1)
        # TODO: We don't actually die, just hang. Need to fix this.


def _exit(rc):
    """
    Immediately terminates this process with the given return code.

    This function is mainly here to be mocked out in UTs.
    """
    os._exit(rc)  # pragma nocover


class TrackedAsyncResult(AsyncResult):
    """
    An AsyncResult that tracks if any exceptions are leaked.
    """
    def __init__(self, tag):
        super(TrackedAsyncResult, self).__init__()
        self.__ref = ExceptionTrackingRef(self, _reap_ref)
        self.__ref.tag = tag

    def set_exception(self, exception):
        self.__ref.exception = exception
        return super(TrackedAsyncResult, self).set_exception(exception)

    def get(self, block=True, timeout=None):
        try:
            result = super(TrackedAsyncResult, self).get(block=block,
                                                         timeout=timeout)
        finally:
            # Someone called get so any exception can't be leaked.  Discard it.
            self.__ref.exception = None
        return result


def actor_event(fn):
    method_name = fn.__name__
    @functools.wraps(fn)
    def queue_fn(self, *args, **kwargs):
        # Police that cross-actor calls must be explicit about blocking.
        on_same_greenlet = (self.greenlet == gevent.getcurrent())
        async_set = "async" in kwargs
        async = kwargs.pop("async", False)
        # TODO: Why do we disallow async messages to same greenlet?
        assert not (on_same_greenlet and async), \
            "Async call to own queue, deadlocks if queue full."
        if (not on_same_greenlet and
                not async and
                _log.isEnabledFor(logging.DEBUG)):
            calling_file,  line_no, func, _ = traceback.extract_stack()[-2]
            calling_file = os.path.basename(calling_file)
            _log.debug("BLOCKING CALL: %s:%s:%s", calling_file, line_no, func)
        if on_same_greenlet:
            # Bypass the queue if we're already on the same greenlet.  This
            # is both useful and avoids deadlock.
            # TODO: if we remove the "no async to same greenlet" only do if
            # this is asynchronous.
            _log.debug("Message processed locally : %s", method_name)
            return fn(self, *args, **kwargs)
        else:
            assert async_set, "Cross-actor calls must specify async arg."
        result = TrackedAsyncResult(method_name)
        partial = functools.partial(fn, self, *args, **kwargs)

        if self._event_queue.full():
            _log.warn("Queue for %s full, this greenlet may block", self)
        # Only block on the queue if the greenlet is running or we could block
        # forever.
        # TODO: But if we allow blocking, then we can hit deadlock if enough work
        # comes in. Hence we can never allow blocking, surely, which in the process
        # means that the logic about disallowing async messages to same greenlet
        # above is not right.
        greenlet_running = bool(self.greenlet)
        allow_block = greenlet_running or self.skip_running_check
        msg = Message(partial, [result], self.name)
        _log.debug("Message sent : %s", msg)
        self._event_queue.put(msg,
                              block=allow_block)
        if async:
            return result
        else:
            return result.get()
    queue_fn.func = fn
    return queue_fn


class Actor(object):
    """
    Class that contains a queue and a greenlet serving that queue.
    """

    queue_size = DEFAULT_QUEUE_SIZE
    """Maximum length of the event queue before caller will be blocked."""

    batch_delay = None
    """
    Delay in seconds imposed after receiving first message before processing
    the messages in a batch.  Higher values encourage batching.
    """

    max_ops_before_yield = 10000
    """Number of calls to self._maybe_yield before it yields"""

    def __init__(self, queue_size=None, qualifier=None):
        queue_size = queue_size or self.queue_size
        self._event_queue = Queue(maxsize=queue_size)
        self.greenlet = gevent.Greenlet(self._loop)
        self._op_count = 0
        self._current_msg = None
        self.skip_running_check = False
        self.started = False

        # Logging parameters
        self.qualifier = qualifier
        if qualifier:
            self.name = "%s(%s)" % (self.__class__.__name__, qualifier)
        else:
            self.name = self.__class__.__name__

    # TODO: Can we just start the greenlet always?
    # There is some craziness about actors that are in CREATED state, where
    # pending a previous iteration shutting down.
    def start(self):
        assert not self.greenlet, "Already running"
        _log.debug("Starting %s", self)
        self.started = True
        self.greenlet.start()
        return self

    def _loop(self):
        """
        Main greenlet loop, repeatedly runs _step().  Doesn't return normally.
        """
        try:
            while True:
                self._step()
        except:
            _log.exception("Exception killed %s", self)
            raise

    def _step(self):
        """
        Run one iteration of the event loop for this actor.  Mainly
        broken out to allow the UTs to single-step an Actor.

        It also has the subtle side effect of introducing a new local
        scope so that our variables die before we block next time.
        """
        # Block waiting for work.
        msg = self._event_queue.get()
        # Then, once we get some, opportunistically pull as much work off the
        # queue as possible.  We call this a batch.
        batch = [msg]
        if self.batch_delay and not self._event_queue.full():
            # If requested by our subclass, delay the start of the batch to
            # allow more work to accumulate.
            gevent.sleep(self.batch_delay)
        while not self._event_queue.empty():
            # We're the only ones getting from the queue so this should
            # never fail.
            batch.append(self._event_queue.get_nowait())

        # Start with one batch on the queue but we may get asked to split it
        # if an error occurs.
        batches = [batch]
        num_splits = 0
        while batches:
            # Process the first batch on our queue of batches.  Invariant:
            # we'll either process this batch to completion and discard it or
            # we'll put all the messages back into the batch queue in the same
            # order but batched differently.
            batch = batches.pop(0)
            # Give subclass a chance to filter the batch/update its state.
            batch = self._start_msg_batch(batch)
            assert batch is not None, "_start_msg_batch() should return batch."
            results = []  # Will end up same length as batch.
            for msg in batch:
                _log.debug("Message recd : %s", msg)
                self._current_msg = msg
                try:
                    # Actually execute the per-message method and record its
                    # result.
                    result = msg.method()
                except BaseException as e:
                    _log.exception("Exception processing %s", msg)
                    results.append(ResultOrExc(None, e))
                else:
                    results.append(ResultOrExc(result, None))
                finally:
                    self._current_msg = None
            try:
                # Give subclass a chance to post-process the batch.
                self._finish_msg_batch(batch, results)
            except SplitBatchAndRetry:
                # The subclass couldn't process the batch as is (probably
                # because a failure occurred and it couldn't figure out which
                # message caused the problem).  Split the batch into two and
                # re-run it.
                _log.warn("Splitting batch to retry.")
                self._split_batch(batch, batches)

                num_splits += 1
                continue
            except BaseException as e:
                # Report failure to all.
                _log.exception("_on_batch_processed failed.")
                results = [(None, e)] * len(results)

            # Batch complete and finalized, set all the results.
            assert len(batch) == len(results)
            for msg, (result, exc) in zip(batch, results):
                for future in msg.results:
                    if exc is not None:
                        future.set_exception(exc)
                    else:
                        future.set(result)
        if num_splits > 0:
            _log.warn("Split batches complete. Number of splits: %s",
                      num_splits)

    @staticmethod
    def _split_batch(batch, batches):
        assert len(batch) > 1, "Batch too small to split"
        # Split the batch.
        split_point = len(batch) // 2
        _log.debug("Split-point = %s", split_point)
        batch_a = batch[:split_point]
        batch_b = batch[split_point:]
        if batches:
            # Optimization: there's another batch already queued,
            # push the second half of this batch onto the front of
            # that one.
            _log.debug("Split batch but found a subsequent batch, "
                       "coalescing with that.")
            next_batch = batches[0]
            next_batch[:0] = batch_b
        else:
            _log.debug("Split batch but no more batches in queue.")
            batches[:0] = [batch_b]
        batches[:0] = [batch_a]

    def _start_msg_batch(self, batch):
        """
        Called before processing a batch of messages to give subclasses
        a chance to filter the batch.  Implementations must ensure that
        every AsyncResult in the batch is correctly set.  Usually, that
        means combining them into one list.

        It is usually easier to build up a batch of changes to make in the
        @actor_event-decorated methods and then process them in
        _post_process_msg_batch().

        Intended to be overridden.  This implementation simply returns the
        input batch.

        :param list[Message] batch:
        """
        return batch

    def _finish_msg_batch(self, batch, results):
        """
        Called after a batch of events have been processed from the queue
        before results are set.

        Intended to be overridden.  This implementation does nothing.

        Exceptions raised by this method are propagated to all messages in the
        batch, overriding the existing results.  It is recommended that the
        implementation catches appropriate exceptions and maps them back
        to the correct entry in results.

        :param list[ResultOrExc] results: Pairs of (result, exception)
            representing the result of each message-processing function.
            Only one of the values is set.  Updates to the list alter the
            result send to any waiting listeners.
        :param list[Message] batch: The input batch, always the same length as
            results.
        """
        pass

    def _maybe_yield(self):
        self._op_count += 1
        if self._op_count >= self.max_ops_before_yield:
            gevent.sleep()
            self._op_count = 0

    def __str__(self):
        return self.__class__.__name__ + "<queue_len=%s,live=%s,msg=%s>" % (
            self._event_queue.qsize(),
            bool(self.greenlet),
            self._current_msg
        )


class SplitBatchAndRetry(Exception):
    """
    Exception that may be raised by _finish_msg_batch() to cause the
    batch of messages to be split, each message to be re-executed and
    then the smaller batches delivered to _finish_msg_batch() again.
    """
    pass


def wait_and_check(async_results):
    for r in async_results:
        r.get()
