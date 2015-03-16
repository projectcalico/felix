# Copyright (c) Metaswitch Networks 2015. All rights reserved.
import collections
import functools

import logging
from calico.felix.actor import Actor, actor_event

_log = logging.getLogger(__name__)


class ReferenceManager(Actor):
    """
    Actor that manages the life cycle of a collection of other Actors
    by name.  Users can request a reference to an actor by name using
    get_ind_incref() and then (they must) return it by calling decref().

    Consecutive calls to incref return the same actor.  Actors are only
    cleaned up when their reference count hits zero.

    Users who obtain a reference through get_and_incref() must stop
    using the reference before calling decref().
    """

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
            assert hasattr(obj, "on_unreferenced")
            if object_id in self.cleanup_futures:
                # ...but, if we have a pending deletion, queue the new actor's
                # start up behind it.
                _log.warn("Pending cleanup for %s; queueing start of "
                          "new object.", object_id)
                # Hint ot he actor that it'll start running eventually so it
                # doesn't assert if its queue gets full.
                obj.skip_running_check = True
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
            self._queue_cleanup(object_id)

    def _create(self, object_id):
        raise NotImplementedError()  # pragma nocover

    def _on_object_activated(self, object_id, obj):
        raise NotImplementedError()  # pragma nocover

    def _queue_cleanup(self, dead_object_id):
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
        Callback we queue when deleting an ProfileRules Actor.
        checks that the Actor is still unreferenced before cleaning
        it up.
        """
        if self.cleanup_futures.get(object_id) is future:
            # Callback from the most recent cleanup, actually clean up the
            # state.
            del self.cleanup_futures[object_id]