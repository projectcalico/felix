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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/projectcalico/felix/dataplane/windows/hns"
	log "github.com/sirupsen/logrus"
)

const (
	// static rule file name
	staticFileName = "static-rules.json"
)

type staticACLRule struct {
	Type            hns.PolicyType
	Id              string // An ID has to be provided for flow logs.
	Protocols       string `json:"Protocols,omitempty"`
	Action          hns.ActionType
	Direction       hns.DirectionType
	LocalAddresses  string       `json:"LocalAddresses,omitempty"`
	RemoteAddresses string       `json:"RemoteAddresses,omitempty"`
	LocalPorts      string       `json:"LocalPorts,omitempty"`
	RemotePorts     string       `json:"RemotePorts,omitempty"`
	RuleType        hns.RuleType `json:"RuleType"`
	Priority        uint16
}

func (p staticACLRule) ToHnsACLPolicy(prefix string) (*hns.ACLPolicy, error) {
	if len(p.Id) == 0 {
		return nil, fmt.Errorf("Id is missing")
	}
	if p.Type != hns.ACL {
		return nil, fmt.Errorf("Type is not ACL")
	}
	if (p.RuleType != hns.Host) && (p.RuleType != hns.Switch) {
		return nil, fmt.Errorf("RuleType %s is invalid", p.RuleType)
	}
	if (p.Action != hns.Allow) && (p.Action != hns.Block) {
		return nil, fmt.Errorf("Action %s is invalid", p.Action)
	}
	if (p.Direction != hns.In) && (p.Direction != hns.Out) {
		return nil, fmt.Errorf("Direction %s is invalid", p.Direction)
	}

	return &hns.ACLPolicy{
		Type:            p.Type,
		Id:              prefix + "-" + p.Id,
		Protocols:       p.Protocols,
		Action:          p.Action,
		Direction:       p.Direction,
		LocalAddresses:  p.LocalAddresses,
		RemoteAddresses: p.RemoteAddresses,
		LocalPorts:      p.LocalPorts,
		RemotePorts:     p.RemotePorts,
		RuleType:        p.RuleType,
		Priority:        p.Priority,
	}, nil
}

type staticEndpointPolicies struct {
	Provider string `json:"Provider"`
	Version  string `json:"Version"`
	Rules    []struct {
		Name  string        `json:"Name"`
		Value staticACLRule `json:"Value"`
	} `json:"Rules"`
}

// Read ACL policy rules from static rule file.
func readStaticRules() (policies []*hns.ACLPolicy) {
	rootDir := filepath.Dir(os.Args[0])
	ruleFile := filepath.Join(rootDir, staticFileName)

	if _, err := os.Stat(ruleFile); os.IsNotExist(err) {
		log.Infof("Ignoring absent static rule file: %v", ruleFile)
		return
	}
	data, err := ioutil.ReadFile(ruleFile)
	if err != nil {
		log.WithError(err).Errorf("Failed to read static rule file.")
		return
	}

	staticPolicies := staticEndpointPolicies{}

	if err = json.Unmarshal(data, &staticPolicies); err != nil {
		log.WithError(err).Errorf("Failed to read static rule file.")
		return
	}

	if len(staticPolicies.Provider) == 0 {
		log.WithError(err).Errorf("Provider is not specified")
		return
	}

	for _, r := range staticPolicies.Rules {
		if r.Value.Type != hns.ACL {
			log.WithField("static rules", r.Value).Errorf("Incorrect static rule")
			continue
		}
		hnsRule, err := r.Value.ToHnsACLPolicy(staticPolicies.Provider)
		if err != nil {
			log.WithError(err).Errorf("Failed to convert static rule to ACL rule.")
			continue
		}
		log.WithField("static ACL rules", hnsRule).Info("Reading static ACL rules")
		policies = append(policies, hnsRule)
	}

	return
}
