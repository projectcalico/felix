# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
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
felix.tracking
~~~~~~~~~~~~~~

Function to support tracking of updates and status reporting.
"""
import gevent
from calico import monotonic

import logging
import weakref
import blist

_log = logging.getLogger(__name__)


class UpdateMonitor(object):
    def __init__(self):
        # Sorted dictionary from update ID to WorkTracker.
        self._trackers = blist.sorteddict()
        # Highest update ID which is complete and all lower IDs are also
        # complete.
        self.complete_hwm = None
        self.seen_hwm = None
        gevent.spawn(self._loop)

    def tracker(self, update_id, replace_all=False, tag=None):
        """
        Create a new WorkTracker.

        :param update_id: ID for the update, required to be monotonically
            increasing.  For example, the etcd_index.
        :param replace_all:  True if this call should erase all previous
            history.
        :param tag: Opaque string, used to identify the type/meaning of the
            update.
        """
        if replace_all:
            self._trackers.clear()
            self.complete_hwm = None
            self.seen_hwm = None
        self.seen_hwm = max(self.seen_hwm, update_id)
        tracker = WorkTracker(self, update_id, tag=tag)
        self._trackers[update_id] = tracker
        return tracker

    def on_work_complete(self, tracker):
        """
        Called by a WorkTracker when the work it is tracking is complete.
        """
        to_delete = []
        for up_id, tracker in self._trackers.iteritems():
            if tracker.finished:
                to_delete.append(up_id)
                self.complete_hwm = max(tracker.update_id,
                                           self.complete_hwm)
            else:
                break
        for up_id in to_delete:
            self._trackers.pop(up_id, None)

        self._trackers.pop(tracker.update_id, None)

    def _loop(self):
        while True:
            gevent.sleep(10)
            _log.info("Highest seen: %s complete: %s; outstanding (%s):",
                      self.seen_hwm, self.complete_hwm, len(self._trackers))
            _tracker_copy = self._trackers.copy()
            for k, v in _tracker_copy.iteritems():
                _log.info("Work item %s: %s", k, v)
                if v.time_since_last_update > 10:
                    _log.warning("Work item %s has gone 10s without update")


class _TrackerBase(object):
    """
    Abstract base class for Trackers, mainly here so we can create a
    dummy tracker to use when tracking is disabled.
    """

    def split_work(self, number=1):
        pass

    def work_complete(self, number=1):
        pass

    def on_error(self, message):
        pass

    def touch(self):
        pass

    @property
    def time_since_last_update(self):
        return NotImplemented

    @property
    def finished(self):
        return True


class WorkTracker(_TrackerBase):
    def __init__(self, monitor, update_id, tag=None):
        _log.debug("Creating tracker for %s, %s", update_id, tag)
        self._monitor = weakref.proxy(monitor)  # Avoid ref cycle.
        self._work_count = 1
        self.start_time = monotonic.monotonic_time()
        self.last_update_time = self.start_time
        self.last_error = None
        self.update_id = update_id
        self.tag = tag

    def split_work(self, number=1):
        _log.debug("%s Adding %s extra work items", self, number)
        self.touch()
        self._work_count += number

    def touch(self):
        now = monotonic.monotonic_time()
        _log.debug("%s Refreshing last-update timestamp.  Now %.2f",
                   self, self.last_update_time, now)
        self.last_update_time = now

    def work_complete(self, number=1):
        _log.debug("%s Adding %s work items as complete", self, number)
        self.touch()
        self._work_count -= number
        assert self._work_count >= 0
        if self.finished:
            self._monitor.on_work_complete(self)

    def on_error(self, message):
        _log.error("%s Error logged: %s", self, message)
        self.touch()
        self.last_error = message

    @property
    def time_since_last_update(self):
        now = monotonic.monotonic_time()
        return now - self.last_update_time

    @property
    def finished(self):
        return self._work_count == 0

    def __str__(self):
        return (self.__class__.__name__ +
                "<tag=%s,id=%s,count=%s,last=%.2f>" % (
                    self.tag,
                    self.update_id,
                    self._work_count,
                    self.time_since_last_update,
                ))


DUMMY_TRACKER = _TrackerBase()
