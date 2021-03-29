// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package arp

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
)

var (
	parsingRegexp = regexp.MustCompile(`Unicast reply from.*\[([0-9a-fA-f:]+)]`)
)

func Ping(addr net.IP, iface string) (net.HardwareAddr, error) {
	var args []string
	if iface != "" {
		args = append(args, "-I", iface)
	}
	args = append(args,
		"-f",      // Stop on first reply.
		"-c", "5", // Maximum of 5 pings.
		"-i", "1", // 1 second interval.
	)
	cmd := exec.Command("arping", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run arpping: %w", err)
	}

	// Expecting output like this:
	//
	// ARPING 192.168.4.1 from 192.168.4.117 veth1234
	// Unicast reply from 192.168.4.1 [50:C7:BF:F5:38:17]  6.609ms
	// Sent 1 probes (1 broadcast(s))
	// Received 1 response(s)
	submatches := parsingRegexp.FindSubmatch(out)
	if submatches == nil {
		return nil, fmt.Errorf("failed to parse arping output: %s", string(out))
	}
	rawMAC := string(submatches[1])
	mac, err := net.ParseMAC(rawMAC)
	if err != nil {
		return nil, fmt.Errorf("bad MAC address arping output: %w", err)
	}
	return mac, nil
}
