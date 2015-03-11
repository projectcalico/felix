# Copyright (c) Metaswitch Networks 2015. All rights reserved.

import logging
import functools
import collections
import weakref
import sys
import gevent
import os
from gevent.event import AsyncResult
from gevent.queue import Queue, Full

_log = logging.getLogger(__name__)


DEFAULT_QUEUE_SIZE = 10


Message = collections.namedtuple("Message", ("function", "result"))


_refs = {}
_ref_idx = 0


class ExceptionTrackingRef(weakref.ref):
    def __init__(self, obj, callback):
        super(ExceptionTrackingRef, self).__init__(obj, callback)
        self.exception = None
        self.tag = None
        global _ref_idx
        self.idx = _ref_idx
        _ref_idx += 1
        _refs[_ref_idx] = self


def _reap_ref(ref):
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
        assert "async" in kwargs
        if not kwargs.get("async") and _log.isEnabledFor(logging.DEBUG):
            import traceback, os
            calling_file,  line_no, func, _ = traceback.extract_stack()[-2]
            calling_file = os.path.basename(calling_file)
            _log.debug("BLOCKING CALL: %s:%s:%s", calling_file, line_no, func)
        async = kwargs.pop("async", False)
        if not async and self.greenlet == gevent.getcurrent():
            # Bypass the queue if we're already on the same greenlet.  This
            # is both useful and avoids deadlock.
            return fn(self, *args, **kwargs)
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