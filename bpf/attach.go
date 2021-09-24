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
	"os"
	"path"

	log "github.com/sirupsen/logrus"
)

type AttachedProgInfo struct {
	Object string `json:"object"`
	Hash   string `json:"hash"`
}

// Check if a hash file exists for an Attach Point and the content matches
// the Attach Point's fields
func VerifyProgHash(iface, hook, object string) (bool, string, error) {
	var (
		progInfo       AttachedProgInfo
		bytesToRead    []byte
		calculatedHash string
		err            error
	)

	if calculatedHash, err = sha256OfFile(object); err != nil {
		return false, "", err
	}

	name := iface + "_" + hook + ".json"
	filename := path.Join(RuntimeDir, name)
	if bytesToRead, err = ioutil.ReadFile(filename); err != nil {
		return false, calculatedHash, err
	}

	if err = json.Unmarshal(bytesToRead, &progInfo); err != nil {
		return false, calculatedHash, err
	}

	if progInfo.Hash == calculatedHash && progInfo.Object == object {
		return true, calculatedHash, nil
	}

	return false, calculatedHash, nil
}

// Store an Attach Point's object name and its hash in a file
// to skip reattaching it in future. The file name is
// [iface name]_[hook name]. For example, eth0_tc_egress.json
func SaveProgHash(iface, hook, object, hash string) error {
	var progInfo = AttachedProgInfo{
		Object: object,
		Hash:   hash,
	}

	if err := os.MkdirAll(RuntimeDir, 0600); err != nil {
		return err
	}

	bytesToWrite, err := json.Marshal(progInfo)
	if err != nil {
		return err
	}

	name := iface + "_" + hook + ".json"
	filename := path.Join(RuntimeDir, name)
	if err = ioutil.WriteFile(filename, bytesToWrite, 0600); err != nil {
		return err
	}

	return nil
}

// Remove the hash file of an Attach Point from disk
func RemoveProgHash(iface, hook string) error {
	name := iface + "_" + hook + ".json"
	filename := path.Join(RuntimeDir, name)
	if err := os.Remove(filename); err != nil {
		return err
	}
	return nil
}

// Delete /var/run/calico/bpf and its content. Then create the same
// directory to start with a clean state
func CleanAndSetupHashDir() {
	if err := os.Remove(RuntimeDir); err != nil {
		log.Warn("Failed to remove BPF hash directory: ", err)
	}
	if err := os.MkdirAll(RuntimeDir, 0600); err != nil {
		log.Warn("Failed to create BPF hash directory: ", err)
	}
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
