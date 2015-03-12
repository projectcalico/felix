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


Message = collections.namedtuple("Message", ("function", "result"))


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


def _reap_ref(ref):
    """
    Called when a TrackedAsyncResult gets GCed.
    :param ExceptionTrackingRef ref: The ref that may contain a leaked
        exception.
    """
    assert isinstance(ref, ExceptionTrackingRef)
    del _refs[ref.idx]
    if ref.exception:
        _log.error("TrackedAsyncResult %s was leaked with exception %r",
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

    def __init__(self, queue_size=DEFAULT_QUEUE_SIZE):
        self._event_queue = Queue(maxsize=queue_size)
        self.greenlet = gevent.Greenlet(self._loop)

    def start(self):
        assert not self.greenlet, "Already running"
        _log.debug("Starting %s", self)
        self.greenlet.start()
        return self

    def _loop(self):
        while True:
            msg = self._event_queue.get()
            assert isinstance(msg.result, AsyncResult)
            try:
                result = msg.function()
            except BaseException as e:
                _log.exception("Exception on loop")
                msg.result.set_exception(e)
            else:
                msg.result.set(result)


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
        self._event_queue.put(Message(function=partial, result=result),
                              block=self.greenlet)
        if async:
            return result
        else:
            return result.get()
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
