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
	"net"
	"testing"

	. "github.com/onsi/gomega"
)

const input = `ARPING 192.168.4.1 from 192.168.4.117 wlp59s0
Unicast reply from 192.168.4.1 [50:C7:B1:F5:38:17]  5.614ms
Sent 1 probes (1 broadcast(s))
Received 1 response(s)
`

func TestParse(t *testing.T) {
	RegisterTestingT(t)
	mac, err := parseArpingOutput([]byte(input))
	Expect(err).NotTo(HaveOccurred())
	Expect(mac).To(Equal(net.HardwareAddr{0x50, 0xc7, 0xb1, 0xf5, 0x38, 0x17}))

	mac, err = parseArpingOutput([]byte(`garbage`))
	Expect(err).To(HaveOccurred())
	Expect(mac).To(BeNil())
}
