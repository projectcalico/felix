// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/felix/bpf"
)

func Map(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/cali_v4_arp",
		Type:       "lru_hash",
		KeySize:    4,     // IPv4
		ValueSize:  2 * 6, // srd + dst MAC address
		MaxEntries: 10000, // max number of node that can forward nodeports to a single node
		Name:       "cali_v4_arp",
		Version:    2,
	})
}
