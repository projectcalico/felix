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

// +build !cgo

package libbpf

type Obj struct {
}

type Link struct {
}

type TCOpts struct {
}

func OpenObject(filename, ifaceName, hook string) (*Obj, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) AttachKprobe(progName, fn string) (*Link, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) AttachClassifier(secName, ifName, hook string) error {
	panic("LIBBPF syscall stub")
}

func CreateQDisc(ifName string) error {
	panic("LIBBPF syscall stub")
}

func RemoveQDisc(ifName string) error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) UpdateJumpMap(mapName, progName string, mapIndex int) error {
	panic("LIBBPF syscall stub")
}

func (l *Link) Close() error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) Close() error {
	panic("LIBBPF syscall stub")
}

func GetProgID(ifaceName, hook string, opts *TCOpts) (int, error) {
	panic("LIBBPF syscall stub")
}

