// Copyright (c) 2016 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calc

import (
	"github.com/golang/glog"
	"github.com/projectcalico/calico/go/felix/config"
	"github.com/projectcalico/calico/go/felix/proto"
	"github.com/projectcalico/calico/go/felix/store"
	"github.com/tigera/libcalico-go/lib/backend/api"
	"github.com/tigera/libcalico-go/lib/backend/model"
	"time"
)

const (
	tickInterval    = 10 * time.Millisecond
	leakyBucketSize = 10
)

type AsyncCalcGraph struct {
	Dispatcher   *store.Dispatcher
	inputEvents  chan interface{}
	outputEvents chan<- interface{}
	eventBuffer  *EventBuffer
	beenInSync   bool

	flushTicks       <-chan time.Time
	flushLeakyBucket int
	dirty            bool
}

func NewAsyncCalcGraph(conf *config.Config, outputEvents chan<- interface{}) *AsyncCalcGraph {
	eventBuffer := NewEventBuffer(conf)
	dispatcher := NewCalculationGraph(eventBuffer, conf.FelixHostname)
	g := &AsyncCalcGraph{
		inputEvents:  make(chan interface{}, 10),
		outputEvents: outputEvents,
		Dispatcher:   dispatcher,
		eventBuffer:  eventBuffer,
	}
	eventBuffer.Callback = g.onEvent
	return g
}

func (acg *AsyncCalcGraph) OnUpdates(updates []model.KVPair) {
	glog.V(4).Infof("Got %v updates; queueing", len(updates))
	acg.inputEvents <- updates
}

func (acg *AsyncCalcGraph) OnStatusUpdated(status api.SyncStatus) {
	glog.V(4).Infof("Status updated: %v; queueing", status)
	acg.inputEvents <- status
}

func (acg *AsyncCalcGraph) loop() {
	glog.V(1).Info("AsyncCalcGraph running")
	for {
		select {
		case update := <-acg.inputEvents:
			switch update := update.(type) {
			case []model.KVPair:
				// Update; send it to the dispatcher.
				glog.V(4).Info("Pulled []KVPair off channel")
				acg.Dispatcher.OnUpdates(update)
			case api.SyncStatus:
				// Sync status changed, check if we're now in-sync.
				glog.V(4).Info("Pulled status update off channel")
				acg.Dispatcher.OnStatusUpdated(update)
				if update == api.InSync && !acg.beenInSync {
					glog.V(1).Info("First time we've been in sync")
					acg.onEvent(&proto.InSync{})
					acg.beenInSync = true
				}
			default:
				glog.Fatalf("Unexpected update: %#v", update)
			}
			acg.dirty = true
		case <-acg.flushTicks:
			// Timer tick: fill up the leaky bucket.
			if acg.flushLeakyBucket < leakyBucketSize {
				acg.flushLeakyBucket++
			}
		}
		acg.maybeFlush()
	}
}

// maybeFlush flushed the event buffer if: we know it's dirty and we're not throttled.
func (acg *AsyncCalcGraph) maybeFlush() {
	if !acg.dirty {
		return
	}
	if acg.flushLeakyBucket > 0 {
		glog.V(4).Infof("Not throttled: flushing event buffer")
		acg.flushLeakyBucket--
		acg.eventBuffer.Flush()
		acg.dirty = false
	} else {
		glog.V(4).Infof("Throttled: not flushing event buffer")
	}
}

func (acg *AsyncCalcGraph) onEvent(event interface{}) {
	glog.V(4).Info("Sending output event on channel")
	acg.outputEvents <- event
	glog.V(4).Info("Sent output event on channel")
}

func (acg *AsyncCalcGraph) Start() {
	glog.V(1).Info("Starting AsyncCalcGraph")
	acg.flushTicks = time.Tick(tickInterval)
	go acg.loop()
}
