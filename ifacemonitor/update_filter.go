// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package ifacemonitor

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/ip"
	timeshim "github.com/projectcalico/felix/time"
)

const FlapDampingDelay = 100 * time.Millisecond

func NewUpdateFilter(options ...UpdateFilterOp) *UpdateFilter {
	u := &UpdateFilter{
		Time: timeshim.NewRealTime(),
	}
	for _, op := range options {
		op(u)
	}
	return u
}

type UpdateFilter struct {
	Time timeshim.Time
}

type UpdateFilterOp func(filter *UpdateFilter)

func WithTimeShim(t timeshim.Time) UpdateFilterOp {
	return func(filter *UpdateFilter) {
		filter.Time = t
	}
}

// FilterUpdates filters out updates that occur when IPs are quickly removed and re-added.
// Some DHCP clients flap the IP during an IP renewal, for example.
//
// Algorithm:
// * Maintain a queue of link and address updates per interface.
// * When we see a potential flap (i.e. an IP deletion), defer processing the queue for a while.
// * If the flap resolves itself (i.e. the IP is added back), suppress the IP deletion.
func (u *UpdateFilter) FilterUpdates(ctx context.Context,
	addrOutC chan<- netlink.AddrUpdate, addrInC <-chan netlink.AddrUpdate,
	linkOutC chan<- netlink.LinkUpdate, linkInC <-chan netlink.LinkUpdate) {

	logrus.Debug("FilterUpdates: starting")
	var timerC <-chan time.Time

	type timestampedUpd struct {
		ReadyAt time.Time
		Update  interface{} // AddrUpdate or LinkUpdate
	}

	updatesByIfaceIdx := map[int][]timestampedUpd{}

	for {
		select {
		case <-ctx.Done():
			logrus.Info("FilterUpdates: Context expired, stopping")
			return
		case linkUpd := <-linkInC:
			idx := linkUpd.Index
			if len(updatesByIfaceIdx[int(idx)]) == 0 {
				logrus.Debug("FilterUpdates: link change with empty queue, short circuit.")
				linkOutC <- linkUpd
				continue
			}
			updatesByIfaceIdx[int(idx)] = append(updatesByIfaceIdx[int(idx)],
				timestampedUpd{
					ReadyAt: u.Time.Now().Add(FlapDampingDelay),
					Update:  linkUpd,
				})
		case addrUpd := <-addrInC:
			logrus.WithField("update", addrUpd).Debug("FilterUpdates: got new update")
			idx := addrUpd.LinkIndex
			oldUpds := updatesByIfaceIdx[idx]

			var readyToSendTime time.Time
			if addrUpd.NewAddr {
				if len(oldUpds) == 0 {
					// This is an add for a new IP and there's nothing else in the queue for this interface.
					// Short circuit.
					logrus.Debug("FilterUpdates: add with empty queue, short circuit.")
					addrOutC <- addrUpd
					continue
				}

				// Else, there's something else in the queue, need to process the queue...
				logrus.Debug("FilterUpdates: add with non-empty queue.")
				readyToSendTime = u.Time.Now()
			} else {
				logrus.Debug("FilterUpdates: delete.")
				readyToSendTime = u.Time.Now().Add(FlapDampingDelay)
			}
			upds := oldUpds[:0]
			for _, upd := range oldUpds {
				logrus.WithField("previous", upd).Debug("FilterUpdates: examining previous update.")
				if oldAddrUpd, ok := upd.Update.(netlink.AddrUpdate); ok {
					if ip.IPNetsEqual(&oldAddrUpd.LinkAddress, &addrUpd.LinkAddress) {
						// New update for the same IP, suppress the old update
						logrus.WithField("address", oldAddrUpd.LinkAddress.String()).Debug(
							"Received update for same IP within a short time, squashed the update.")
						// To prevent continuous flapping from delaying route updates forever, take the timestamp of the
						// first update.
						readyToSendTime = upd.ReadyAt
						continue
					}
				}
				upds = append(upds, upd)
			}
			upds = append(upds, timestampedUpd{ReadyAt: readyToSendTime, Update: addrUpd})
			updatesByIfaceIdx[idx] = upds
		case <-timerC:
			logrus.Debug("FilterUpdates: timer popped.")
		}
		var nextUpdTime time.Time
		for idx, upds := range updatesByIfaceIdx {
			logrus.WithField("ifaceIdx", idx).Debug("FilterUpdates: examining updates for interface.")
			for len(upds) > 0 {
				firstUpd := upds[0]
				if u.Time.Since(firstUpd.ReadyAt) >= 0 {
					// Either update is old enough to prevent flapping or it's an address being added.
					// Ready to send...
					logrus.WithField("update", firstUpd).Debug("FilterUpdates: update ready to send.")
					switch u := firstUpd.Update.(type) {
					case netlink.AddrUpdate:
						addrOutC <- u
					case netlink.LinkUpdate:
						linkOutC <- u
					}
					upds = upds[1:]
				} else {
					// Update is too new, figure out when it'll be safe to send it.
					logrus.WithField("update", firstUpd).Debug("FilterUpdates: update not ready.")
					if nextUpdTime.IsZero() || firstUpd.ReadyAt.Before(nextUpdTime) {
						nextUpdTime = firstUpd.ReadyAt
					}
					break
				}
			}
			if len(upds) == 0 {
				logrus.WithField("ifaceIdx", idx).Debug("FilterUpdates: no more updates for interface.")
				delete(updatesByIfaceIdx, idx)
			} else {
				logrus.WithField("ifaceIdx", idx).WithField("num", len(upds)).Debug(
					"FilterUpdates: still updates for interface.")
				updatesByIfaceIdx[idx] = upds
			}
		}
		if !nextUpdTime.IsZero() {
			// Need to schedule a retry.
			delay := u.Time.Until(nextUpdTime)
			if delay <= 0 {
				delay = 1
			}
			logrus.WithField("delay", delay).Debug("FilterUpdates: calculated delay.")
			timerC = u.Time.After(delay)
		} else {
			logrus.Debug("FilterUpdates: no more updates to send, disabling timer.")
			timerC = nil
		}
	}
}
