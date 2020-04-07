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

package wireguard

import (
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// timeIface is our shim interface to the time package.
type timeIface interface {
	Now() time.Time
	Since(t time.Time) time.Duration
}

func newTimeIface() timeIface {
	return realTime{}
}

// realTime is the real implementation of timeIface, which calls through to the real time package.
type realTime struct{}

func (realTime) Now() time.Time {
	return time.Now()
}

func (realTime) Since(t time.Time) time.Duration {
	return time.Since(t)
}

var _ timeIface = realTime{}

// WireguardClient is a shim interface for mocking linkClient calls to manage the wireguard key and peer configuration.
type WireguardClient interface {
	Close() error
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

func newWireguardClient() (WireguardClient, error) {
	return wgctrl.New()
}

// NetlinkClient is a shim interface for mocking netlink calls to manage the wireguard interface lifecycle.
type NetlinkClient interface {
	LinkByName(name string) (netlink.Link, error)
	LinkAdd(link netlink.Link) error
	LinkDel(link netlink.Link) error
	LinkSetMTU(link netlink.Link, mtu int) error
	LinkSetUp(link netlink.Link) error
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	AddrDel(link netlink.Link, addr *netlink.Addr) error
	RuleList(family int) ([]netlink.Rule, error)
	RuleAdd(rule *netlink.Rule) error
	RuleDel(rule *netlink.Rule) error
	Close() error
}

func newLinkClient() (NetlinkClient, error) {
	return &realNetlinkClient{}, nil
}

type realNetlinkClient struct{}

func (r *realNetlinkClient) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (r *realNetlinkClient) LinkAdd(link netlink.Link) error {
	return netlink.LinkAdd(link)
}

func (r *realNetlinkClient) LinkDel(link netlink.Link) error {
	return netlink.LinkDel(link)
}

func (r *realNetlinkClient) LinkSetMTU(link netlink.Link, mtu int) error {
	return netlink.LinkSetMTU(link, mtu)
}

func (r *realNetlinkClient) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (r *realNetlinkClient) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return netlink.AddrList(link, family)
}

func (r *realNetlinkClient) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrAdd(link, addr)
}

func (r *realNetlinkClient) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrDel(link, addr)
}

func (r *realNetlinkClient) RuleList(family int) ([]netlink.Rule, error) {
	return netlink.RuleList(family)
}

func (r *realNetlinkClient) RuleAdd(rule *netlink.Rule) error {
	return netlink.RuleAdd(rule)
}

func (r *realNetlinkClient) RuleDel(rule *netlink.Rule) error {
	return netlink.RuleDel(rule)
}

func (r *realNetlinkClient) Close() error {
	return nil
}
