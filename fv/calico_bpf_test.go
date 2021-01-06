// +build fvtests

// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package fv_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/fv/utils"
)

var _ = DescribeTable("_BPF-SAFE_ calico-bpf invocation",
	func(ok bool, args ...string) {
		err := utils.RunMayFail("../bin/calico-bpf", args...)
		if ok {
			Expect(err).To(Succeed())
		} else {
			Expect(err).To(HaveOccurred())
		}
	},
	Entry("", true, "ipsets", "dump", "--debug"),
	Entry("", false, "ipsets", "dump", "--rubbish"),
	Entry("", true, "--debug", "ipsets", "dump"),
	Entry("", true, "ipsets", "--debug", "dump"),
)
