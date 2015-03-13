# Copyright (c) Metaswitch Networks 2015. All rights reserved.

import logging
import functools
import collections
import weakref
import sys
import gevent
import os
from gevent.event import AsyncResult
from gevent.queue import Queue

_log = logging.getLogger(__name__)


DEFAULT_QUEUE_SIZE = 10


Message = collections.namedtuple("Message", ("partial", "results"))
ResultOrExc = collections.namedtuple("ResultOrExc", ("result", "exception"))


_refs = {}
_ref_idx = 0


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
        _refs[_ref_idx] = self

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
        os._exit(1)


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


class Actor(object):

    queue_size = DEFAULT_QUEUE_SIZE
    """Maximum length of the event queue before caller will be blocked."""

    batch_delay = None
    """
    Delay in seconds imposed after receiving first message before processing
    the messages in a batch.  Higher values encourage batching.
    """

    def __init__(self, queue_size=None):
        queue_size = queue_size or self.queue_size
        self._event_queue = Queue(maxsize=queue_size)
        self.greenlet = gevent.Greenlet(self._loop)

    def start(self):
        assert not self.greenlet, "Already running"
        _log.debug("Starting %s", self)
        self.greenlet.start()
        return self

    def _loop(self):
        try:
            while True:
                msg = self._event_queue.get()
                batch = [msg]
                if self.batch_delay and not self._event_queue.full():
                    gevent.sleep(self.batch_delay)
                while not self._event_queue.empty():
                    # We're the only ones getting from the queue so this should
                    # never fail.
                    batch.append(self._event_queue.get_nowait())

                results = []
                filtered_batch = self._pre_filter_msg_batch(batch)
                for msg in filtered_batch:
                    try:
                        result = msg.partial()
                    except BaseException as e:
                        _log.exception("Exception processing %s", msg)
                        results.append(ResultOrExc(None, e))
                    else:
                        results.append(ResultOrExc(result, None))
                try:
                    self._finish_msg_batch(batch, results)
                except BaseException as e:
                    # Report failure to all.
                    _log.exception("_on_batch_processed failed.")
                    results = [(None, e)] * len(results)

                for msg, (result, exc) in zip(batch, results):
                    for future in msg.results:
                        if exc is not None:
                            future.set_exception(exc)
                        else:
                            future.set(result)
        except:
            _log.exception("Exception killed %s", self)
            raise

    def _pre_filter_msg_batch(self, batch):
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


def actor_event(fn):
    method_name = fn.__name__
    @functools.wraps(fn)
    def queue_fn(self, *args, **kwargs):
        async_set = "async" in kwargs
        async = kwargs.pop("async", False)
        local_call = not async and self.greenlet == gevent.getcurrent()
        if not local_call and not async and _log.isEnabledFor(logging.DEBUG):
            import traceback, os
            calling_file,  line_no, func, _ = traceback.extract_stack()[-2]
            calling_file = os.path.basename(calling_file)
            _log.debug("BLOCKING CALL: %s:%s:%s", calling_file, line_no, func)
        if local_call:
            # Bypass the queue if we're already on the same greenlet.  This
            # is both useful and avoids deadlock.
            return fn(self, *args, **kwargs)
        else:
            assert async_set, "Cross-actor calls must specify async arg."
        result = TrackedAsyncResult(method_name)
        partial = functools.partial(fn, self, *args, **kwargs)
        self._event_queue.put(Message(partial=partial, results=[result]),
                              block=self.greenlet)
        if async:
            return result
        else:
            return result.get()
    queue_fn.func = fn
    return queue_fn


def wait_and_check(async_results):
    for r in async_results:
        r.get()


class ReferenceManager(Actor):
    def __init__(self):
        super(ReferenceManager, self).__init__()
        self.objects_by_id = {}
        self.ref_counts_by_id = collections.defaultdict(lambda: 0)
        self.cleanup_futures = {}

    @actor_event
    def get_and_incref(self, object_id):
        assert object_id is not None
        if object_id not in self.objects_by_id:
            # Keep it clean: Always create a new object even if we've got a
            # pending deletion...
            obj = self._create(object_id)
            if object_id in self.cleanup_futures:
                # ...but, if we have a pending deletion, queue the new actor's
                # start up behind it.
                _log.warn("Pending cleanup for %s; queueing start of "
                          "new object.", object_id)
                self.cleanup_futures[object_id].rawlink(obj.start)
            else:
                obj.start()
            self.objects_by_id[object_id] = obj
        else:
            obj = self.objects_by_id[object_id]
        if not self._is_active(object_id):
            self._on_object_activated(object_id, obj)
        self.ref_counts_by_id[object_id] += 1
        return obj

    @actor_event
    def decref(self, object_id):
        self.ref_counts_by_id[object_id] -= 1
        ref_count = self.ref_counts_by_id[object_id]
        assert ref_count >= 0, "Ref count dropped below 0: %s" % ref_count
        if ref_count == 0:
            _log.debug("No more references to object with id %s", object_id)
            self._queue_reap(object_id)

    def _create(self, object_id):
        raise NotImplementedError()

    def _on_object_activated(self, object_id, obj):
        raise NotImplementedError()

    def _queue_reap(self, dead_object_id):
        """
        Asks the object to remove itself.  Queues a callback to
        do our cleanup.
        """
        obj = self.objects_by_id.pop(dead_object_id, None)
        self.ref_counts_by_id.pop(dead_object_id)
        f = obj.on_unreferenced(async=True)
        self.cleanup_futures[dead_object_id] = f
        callback = functools.partial(self._on_object_cleanup_complete,
                                     dead_object_id, f, async=True)
        f.rawlink(callback)

    def _is_active(self, object_id):
        return self.ref_counts_by_id.get(object_id, 0) > 0

    @actor_event
    def _on_object_cleanup_complete(self, object_id, future):
        """
        Callback we queue when deleting an ActiveProfile Actor.
        checks that the Actor is still unreferenced before cleaning
        it up.
        """
        if self.cleanup_futures.get(object_id) is future:
            # Callback from the most recent cleanup, actually clean up the
            # state.
            del self.cleanup_futures[object_id]
