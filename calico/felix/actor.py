# Copyright (c) Metaswitch Networks 2015. All rights reserved.

import logging
import gevent
from gevent.event import AsyncResult
from gevent.queue import Queue

_log = logging.getLogger(__name__)


def actor_event(fn):
    fn.actor_event = True
    return fn


class _ActorMetaclass(type):
    def __new__(mcs, name, bases, attrs):

        for key, value in attrs.iteritems():
            if hasattr(value, "actor_event"):
                # We've got an event, replace with a function that queues the input.
                attrs[key] = _make_queue_fn(value)

        return super(_ActorMetaclass, mcs).__new__(mcs, name, bases, attrs)


class Actor(object):
    __metaclass__ = _ActorMetaclass

    def __init__(self):
        self._event_queue = Queue()
        # FIXME should defer to a start method.
        gevent.spawn(self._loop)

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




def _make_queue_fn(event_fn):
    def queue_fn(self, *args, **kwargs):
        future = AsyncResult()
        self._event_queue.put((future, event_fn, args, kwargs))
        return future
    return queue_fn


class RefcountedActor(Actor):

    def __init__(self):
        super(RefcountedActor, self).__init__()
        self.referrers = set()

    @actor_event
    def add_referrer(self, referrer):
        _log.debug("Adding referrer %s", referrer)
        was_in_use = self.in_use
        self.referrers.add(referrer)
        if not was_in_use:
            self._on_has_referrers()

    @actor_event
    def remove_referrer(self, referrer):
        self.referrers.remove(referrer)
        if not self.in_use:
            self._on_has_no_referrers()

    def _on_has_referrers(self):
        pass

    def _on_has_no_referrers(self):
        pass

    @property
    def in_use(self):
        return bool(self.referrers)