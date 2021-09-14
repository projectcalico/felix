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

package bpf

import (
	"io"
	"os"
	"os/exec"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
)

func CheckAttachedProgs(iface, binaryFile string) (bool, string) {
	var loadedProgCSUM []byte

	hashCmd := exec.Command("sha256sum", binaryFile)
	log.Info(binaryFile)
	outBytes, err := hashCmd.Output()
	if err != nil {
		log.Info("zero:", err)
		return false, ""
	}

	calculatedCSUM := strings.Split(string(outBytes), " ")[0]
	log.Info(calculatedCSUM)
	log.Info(len(calculatedCSUM))

	filename := path.Join("/var/lib/calico", iface)
	log.Info("File is ", filename)
	if _, err := os.Stat(filename); err == nil {
		log.Info("HEREE")
		file, err := os.Open(filename)
		if err != nil {
			log.Info("one:", err)
			return false, calculatedCSUM
		}
		defer file.Close()

		//TODO: boundry
		log.Info("Calculated CSUM:", calculatedCSUM)
		log.Info("loaded CSUMM:", loadedProgCSUM)
		_, err = io.ReadFull(file, loadedProgCSUM[:])
		if string(loadedProgCSUM) == calculatedCSUM {
			log.Info("two:")
			return true, calculatedCSUM
		}
	}

	log.Info("three:")
	return false, calculatedCSUM
}

func RememberAttachedProgs(iface, csum string) {
	log.Info("Mansour", iface)
	filename := path.Join("/var/lib/calico", iface)
	file, err := os.Create(filename)
	if err != nil {
		log.Info(err)
	}
	defer file.Close()

	log.Info("Mazdak", csum)
	_, err = io.WriteString(file, csum)
}
