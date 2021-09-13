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

package bpf

import (
	"bufio"
	"os"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

func CheckAttachedProgs(binaryFile, filename string) (bool, []byte) {
	hashCmd := exec.Command("sha256sum", binaryFile)
	outBytes, err := hashCmd.Output()
	if err != nil {
		return false, nil
	}
	log.Info(string(outBytes))

	ifaceInfo := "/var/lib/calico/" + filename
	log.Info(filename)
	if _, err := os.Stat(ifaceInfo); err == nil {
		file, err := os.Open(ifaceInfo)
		if err != nil {
			log.Info(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		information := scanner.Scan()
		log.Info(information)
		return true, outBytes
	}

	return false, nil
}

func RememberAttachedProgs(filename string, csum []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Info(err)
	}
	defer file.Close()
}
