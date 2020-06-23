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

// Copyright (c) 2020  All rights reserved.

package tc

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// TCHook is the hook to which a BPF program should be attached.  This is relative to the host namespace
// so workload PolDirnIngress policy is attached to the HookEgress.
type Hook string

const (
	HookIngress Hook = "ingress"
	HookEgress  Hook = "egress"
)

const (
	CompileFlagHostEp    = 1
	CompileFlagIngress   = 2
	CompileFlagTunnel    = 4
	CompileFlagCgroup    = 8
	CompileFlagWireguard = 16
)

type ToOrFromEp string

const (
	FromEp ToOrFromEp = "from"
	ToEp   ToOrFromEp = "to"
)

type EndpointType string

const (
	EpTypeWorkload  EndpointType = "workload"
	EpTypeHost      EndpointType = "host"
	EpTypeTunnel    EndpointType = "tunnel"
	EpTypeWireguard EndpointType = "wireguard"
)

func SectionName(endpointType EndpointType, fromOrTo ToOrFromEp) string {
	return fmt.Sprintf("calico_%s_%s_ep", fromOrTo, endpointType)
}

var sectionToFlags = map[string]int{}

func init() {
	sectionToFlags[SectionName(EpTypeWorkload, FromEp)] = 0
	sectionToFlags[SectionName(EpTypeWorkload, ToEp)] = CompileFlagIngress
	sectionToFlags[SectionName(EpTypeHost, FromEp)] = CompileFlagHostEp | CompileFlagIngress
	sectionToFlags[SectionName(EpTypeHost, ToEp)] = CompileFlagHostEp
	sectionToFlags[SectionName(EpTypeTunnel, FromEp)] = CompileFlagHostEp | CompileFlagIngress | CompileFlagTunnel
	sectionToFlags[SectionName(EpTypeTunnel, ToEp)] = CompileFlagHostEp | CompileFlagTunnel
	sectionToFlags[SectionName(EpTypeWireguard, FromEp)] = CompileFlagHostEp | CompileFlagIngress | CompileFlagWireguard
	sectionToFlags[SectionName(EpTypeWireguard, ToEp)] = CompileFlagHostEp | CompileFlagWireguard
}

func ProgFilename(epType EndpointType, toOrFrom ToOrFromEp, epToHostDrop, fib, dsr bool, logLevel string) string {
	if epToHostDrop && (epType != EpTypeWorkload || toOrFrom == ToEp) {
		// epToHostDrop only makes sense in the from-workload program.
		logrus.Debug("Ignoring epToHostDrop, doesn't apply to this target")
		epToHostDrop = false
	}
	if fib && (toOrFrom != FromEp) {
		// FIB lookup only makes sense for traffic towards the host.
		logrus.Debug("Ignoring fib enabled, doesn't apply to this target")
		fib = false
	}

	var hostDropPart string
	if epType == EpTypeWorkload && epToHostDrop {
		hostDropPart = "host_drop_"
	}
	fibPart := ""
	if fib {
		fibPart = "fib_"
	}
	dsrPart := ""
	if dsr && ((epType == EpTypeWorkload && toOrFrom == FromEp) || (epType == EpTypeHost)) {
		dsrPart = "dsr_"
	}
	logLevel = strings.ToLower(logLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}
	var epTypeShort string
	switch epType {
	case EpTypeWorkload:
		epTypeShort = "wep"
	case EpTypeHost:
		epTypeShort = "hep"
	case EpTypeTunnel:
		epTypeShort = "tnl"
	case EpTypeWireguard:
		epTypeShort = "wg"
	}
	oFileName := fmt.Sprintf("%v_%v_%s%s%s%v.o",
		toOrFrom, epTypeShort, hostDropPart, fibPart, dsrPart, logLevel)
	return oFileName
}
