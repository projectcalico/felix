# Copyright (c) Metaswitch Networks 2015. All rights reserved.
import collections
import functools

import logging
import weakref
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
        self.pending_ref_callbacks = collections.defaultdict(set)
        self.pending_cleanups = collections.defaultdict(set)
        self.ref_counts_by_id = collections.defaultdict(lambda: 0)

    @actor_event
    def get_and_incref(self, object_id, callback):
        assert object_id is not None
        assert callback is not None

        if object_id not in self.objects_by_id:
            # Keep it clean: Always create a new object even if we've got a
            # pending deletion...
            obj = self._create(object_id)
            self.objects_by_id[object_id] = obj
            self.pending_ref_callbacks[object_id].add(callback)
            self._maybe_start(object_id)
        else:
            obj = self.objects_by_id[object_id]

        self.ref_counts_by_id[object_id] += 1

    @actor_event
    def decref(self, object_id):
        self.ref_counts_by_id[object_id] -= 1
        ref_count = self.ref_counts_by_id[object_id]
        assert ref_count >= 0, "Ref count dropped below 0: %s" % ref_count
        if ref_count == 0:
            _log.debug("No more references to object with id %s", object_id)
            obj = self.objects_by_id.pop(object_id)
            obj.on_unreferenced(async=True)
            self.pending_cleanups[object_id].add(obj)
            self.pending_ref_callbacks.pop(object_id, None)

    @actor_event
    def on_object_startup_complete(self, object_id, obj):
        if self.objects_by_id.get(object_id) is not obj:
            _log.debug("Ignoring on_object_startup_complete for old instance")
            return
        for cb in self.pending_ref_callbacks[object_id]:
            cb(object_id, obj)
        del self.pending_ref_callbacks[object_id]

    @actor_event
    def on_object_cleanup_complete(self, object_id, obj):
        self.pending_cleanups[object_id].discard(obj)
        if not self.pending_cleanups[object_id]:
            del self.pending_cleanups[object_id]
            self._maybe_start(object_id)

    def _maybe_start(self, obj_id):
        if (obj_id in self.pending_ref_callbacks and
                obj_id in self.objects_by_id and
                obj_id not in self.pending_cleanups):
            _log.debug("Object %s is still requested and there are no "
                       "outstanding cleanups.  Starting it.")
            self.objects_by_id[obj_id].start()

    def _create(self, object_id):
        raise NotImplementedError()  # pragma nocover

    def _on_object_activated(self, object_id, obj):
        raise NotImplementedError()  # pragma nocover

    def _is_active(self, object_id):
        return self.ref_counts_by_id.get(object_id, 0) > 0


class RefCountedActor(Actor):
    def __init__(self, manager, obj_id):
        super(RefCountedActor, self).__init__()
        self._manager = weakref.proxy(manager)
        self._id = obj_id

    def _notify_ready(self):
        self._manager.on_object_startup_complete(self._id,
                                                 self, async=True)

    def _notify_cleanup_complete(self):
        self._manager.on_object_cleanup_complete(self._id,
                                                 self, async=True)

    @actor_event
    def on_referenced(self):
        self._notify_ready()

    @actor_event
    def on_unreferenced(self):
        self._notify_cleanup_complete()