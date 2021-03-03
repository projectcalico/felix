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

package policysets

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/dataplane/windows/hns"
)

var rules string = `
{
    "provider": "MyPlatform",
    "rules": [
        {
            "Name": "EndpointPolicy",
            "Value": {
                "Action": "Block",
                "Direction": "Out",
                "Id": "block-server",
                "Priority": 200,
                "Protocol": 6,
                "RemoteAddresses": "10.0.0.1/32",
                "RemotePorts": "80",
                "RuleType": "Switch",
                "Type": "ACL"
            }
        },
        {
            "Name": "EndpointPolicy",
            "Value": {
                "Action": "Allow",
                "Direction": "In",
                "Id": "block-client",
                "Priority": 300,
                "Protocol": 17,
                "RemoteAddresses": "10.0.0.2/32",
                "RemotePorts": "90",
                "RuleType": "Host",
                "Type": "ACL"
            }
        }
    ],
    "version": "0.1.0"
}
`

func TestStaticRuleRendering(t *testing.T) {
	RegisterTestingT(t)

	r := mockReader(rules)
	// Should read rules.
	Expect(readStaticRules(r)).To(Equal([]*hns.ACLPolicy{
		// Default deny rule.
		{Type: hns.ACL, Protocol: 6, Action: hns.Block, Direction: hns.Out, RuleType: hns.Switch,
			Priority: 200, RemoteAddresses: "10.0.0.1/32", RemotePorts: "80"},
		{Type: hns.ACL, Protocol: 17, Action: hns.Allow, Direction: hns.In, RuleType: hns.Host,
			Priority: 300, RemoteAddresses: "10.0.0.2/32", RemotePorts: "90"},
	}), "unexpected rules returned")
}

type mockReader string

func (m mockReader) readData() ([]byte, error) {
	return []byte(string(m)), nil
}
