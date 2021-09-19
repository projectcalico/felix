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
)

type AttachedProgInfo struct {
	Object string `json:"object"`
	Hash   string `json:"hash"`
}

func IsAlreadyAttached(iface, hook, object string) (bool, string, error) {
	var progInfo AttachedProgInfo
	var bytesToRead []byte

	calculatedHash, err := sha256OfFile(object)
	name := iface + "_" + hook + ".json"
	filename := path.Join(RuntimeDir, name)
	if bytesToRead, err = ioutil.ReadFile(filename); err != nil {
		return false, calculatedHash, err
	}

	if err := json.Unmarshal(bytesToRead, &progInfo); err != nil {
		return false, calculatedHash, err
	}

	if progInfo.Hash == calculatedHash && progInfo.Object == object {
		return true, calculatedHash, nil
	}

	return false, calculatedHash, nil
}

func RememberAttachedProg(iface, hook, object, hash string) error {
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
	if err = ioutil.WriteFile(filename, bytesToWrite, 0400); err != nil {
		return err
	}

	return nil
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
