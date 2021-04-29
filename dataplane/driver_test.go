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

package dataplane

import (
	"errors"
	"time"

	"k8s.io/apimachinery/pkg/util/clock"

	"github.com/projectcalico/libcalico-go/lib/health"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AWS EC2 Set source-destination-check Tests", func() {
	It("should retry on error and exit the retry loop on success", func() {
		fc := clock.NewFakeClock(time.Now())
		healthAgg := health.NewHealthAggregator()

		const totalRetries = 6
		count := 0
		// taking jitter into consideration, each fakeClock step should be slightly longer
		fakeClockSteps := []time.Duration{
			40 * time.Second,
			70 * time.Second,
			3 * time.Minute,
			5 * time.Minute,
			9 * time.Minute,
			9 * time.Minute,
			9 * time.Minute,
		}
		var fun = func(option string) error {
			Expect(healthAgg.Summary().Ready).To(BeFalse())

			fc.Step(fakeClockSteps[count])
			count += 1
			if count > totalRetries {
				return nil
			}
			return errors.New("Some AWS EC2 errors")
		}

		awsEC2UpdateSrcDstCheck("Disable", healthAgg, fun, fc)
		Expect(count).To(Equal(1 + totalRetries))
		Expect(healthAgg.Summary().Ready).To(BeTrue())
	})
})
