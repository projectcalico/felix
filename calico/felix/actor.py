# Copyright (c) Metaswitch Networks 2015. All rights reserved.

import logging
import functools
import collections
import gevent
from gevent.event import AsyncResult
from gevent.queue import Queue, Full

_log = logging.getLogger(__name__)


DEFAULT_QUEUE_SIZE = 10


Message = collections.namedtuple("Message", ("partial", "results"))


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
            batch = [msg]
            while not self._event_queue.empty():
                # We're the only ones getting from the queue so this should
                # never fail.
                batch.append(self._event_queue.get_nowait())

            results = []
            for msg in self._filter_message_batch(batch):
                assert isinstance(msg.result, AsyncResult)
                try:
                    result = msg.partial()
                except BaseException as e:
                    _log.exception("Exception processing %s", msg)
                    results.append((None, e))
                else:
                    results.append((result, None))
            try:
                self._on_batch_processed(batch, results)
            except BaseException as e:
                # Take over the final result.
                # FIXME: Better approach?
                _log.exception("_on_batch_processed failed.")
                results[-1] = (None, e)

            for msg, (result, exc) in zip(batch, results):
                for future in msg.results:
                    if exc is not None:
                        future.set_exception(exc)
                    else:
                        future.set(result)

    def _filter_message_batch(self, batch):
        """
        Called before processing a batch of messages to give subclasses
        a chance to filter the batch.  Implementations must ensure that
        every AsyncResult in the batch is correctly set.  Usually, that
        means combining them into one list.

        Intended to be overridden.  This implementation simply returns the
        input batch.

        :param list[Message] batch:
        """
        return batch

    def _on_batch_processed(self, batch):
        """
        Called after a batch of events have been processed from the queue
        before results are set.

        Intended to be overridden.  This implementation does nothing.
        """
        pass


def actor_event(fn):
    @functools.wraps(fn)
    def queue_fn(self, *args, **kwargs):
        async = kwargs.pop("async", False)
        if not async and self.greenlet == gevent.getcurrent():
            # Bypass the queue if we're already on the same greenlet.  This
            # is both useful and avoids deadlock.
            return fn(self, *args, **kwargs)
        result = AsyncResult()
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