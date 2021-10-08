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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

type AttachedProgInfo struct {
	Object string `json:"object"`
	Hash   string `json:"hash"`
	ID     string `json:"id"`
}

// Compute a sha265 hash of the bpf object we are going to attach to an interface and
// match it against the hash we potentially stored before in a json file. Also verify that
// the content of the file matches the Attach Point's fields including program ID, object name
func AlreadyAttachedProg(iface, hook, object, id string) (bool, error) {
	hash, err := sha256OfFile(object)
	if err != nil {
		return false, err
	}

	bytesToRead, err := ioutil.ReadFile(hashFileName(iface, hook))
	if err != nil {
		// If file does not exist, just ignore the err code, and return false
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	var progInfo AttachedProgInfo
	if err = json.Unmarshal(bytesToRead, &progInfo); err != nil {
		return false, err
	}

	// Check the hash and other information we stored before, matches
	// the object we are going to attach now
	if progInfo.Hash == hash && progInfo.Object != "" && progInfo.Object == object &&
		progInfo.ID != "" && progInfo.ID == id {
		return true, nil
	}

	return false, nil
}

// Store an Attach Point's object name and its hash in a file
// to skip reattaching it in future.
func RememberAttachedProg(iface, hook, object, id string) error {
	hash, err := sha256OfFile(object)
	if err != nil {
		return err
	}

	var progInfo = AttachedProgInfo{
		Object: object,
		Hash:   hash,
		ID:     id,
	}

	if err := os.MkdirAll(RuntimeProgDir, 0600); err != nil {
		return err
	}

	bytesToWrite, err := json.Marshal(progInfo)
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(hashFileName(iface, hook), bytesToWrite, 0600); err != nil {
		return err
	}

	return nil
}

// Remove the hash file of an Attach Point from disk
func ForgetAttachedProg(iface, hook string) error {
	err := os.Remove(hashFileName(iface, hook))
	// If the hash file does not exist, just ignore the err code, and return false
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Remove any hash file related to an interface
func ForgetIfaceAttachedProg(iface string) error {
	hooks := []string{"tc_ingress", "tc_egress", "xdp"}
	for _, hook := range hooks {
		err := ForgetAttachedProg(iface, hook)
		if err != nil {
			return err
		}
	}
	return nil
}

// Make sure /var/run/calico/bpf/prog exists. Then remove the
// json files related to interfaces that do not exist
func CleanAttachedProgDir() {
	if err := os.MkdirAll(RuntimeProgDir, 0600); err != nil {
		log.Errorf("Failed to create BPF hash directory. err=%v", err)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Errorf("Failed to get list of interfaces. err=%v", err)
	}

	suffixes := []string{"tc_ingress", "tc_egress", "xdp"}
	expectedJSONFiles := make(map[string]interface{})
	for _, iface := range interfaces {
		for _, suffix := range suffixes {
			expectedJSONFiles[hashFileName(iface.Name, suffix)] = nil
		}
	}

	err = filepath.Walk(RuntimeProgDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if p == RuntimeProgDir {
			return nil
		}
		if _, exists := expectedJSONFiles[p]; !exists {
			err := os.Remove(p)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}

		return nil
	})

	if err != nil {
		log.Debugf("Error in traversing %s. err=%v", RuntimeProgDir, err)
	}
}

// The file name is [iface name]_[hook name]. For example, eth0_tc_egress.json
func hashFileName(iface, hook string) string {
	return path.Join(RuntimeProgDir, iface+"_"+hook+".json")
}

func sha256OfFile(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", fmt.Errorf("failed to open BPF object to calculate its hash: %w", err)
	}
	hasher := sha256.New()
	_, err = io.Copy(hasher, f)
	if err != nil {
		return "", fmt.Errorf("failed to read BPF object to calculate its hash: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
