# Copyright (c) Metaswitch Networks 2015. All rights reserved.

import logging
import functools
import gevent
from gevent.event import AsyncResult
from gevent.queue import Queue, Full

_log = logging.getLogger(__name__)


DEFAULT_QUEUE_SIZE = 10


class Actor(object):

    def __init__(self, queue_size=DEFAULT_QUEUE_SIZE):
        _log.debug("Running Actor.__init__")
        self.running = False
        self._event_queue = Queue(maxsize=queue_size)
        self.greenlet = gevent.Greenlet(self._loop)

    def start(self):
        assert not self.running, "Already running"
        _log.debug("Starting %s", self)
        self.running = True
        self.greenlet.start()
        return self

    def _loop(self):
        while True:
            future, fn, args, kwargs = self._event_queue.get()
            assert isinstance(future, AsyncResult)
            try:
                result = fn(self, *args, **kwargs)
            except BaseException as e:
                _log.exception("Exception on loop")
                future.set_exception(e)
            else:
                future.set(result)


def actor_event(fn):
    @functools.wraps(fn)
    def queue_fn(self, *args, **kwargs):
        future = AsyncResult()
        try:
            self._event_queue.put((future, fn, args, kwargs),
                                  block=self.running)
        except Full:
            _log.exception("Deadlock: full queue when Actor not running")
            raise
        return future
    return queue_fn

