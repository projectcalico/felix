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

package libbpf

import (
	"fmt"
	"unsafe"
	"syscall"

	"github.com/projectcalico/felix/bpf"
)

// #include "libbpf_api.h"
import "C"

type Obj struct {
	obj *C.struct_bpf_object
}

type TCOpts struct {
	opts C.struct_bpf_tc_opts
}

type Map struct {
	bpfMap *C.struct_bpf_map
	bpfObj *C.struct_bpf_object
}

const MapTypeProgrArray = C.BPF_MAP_TYPE_PROG_ARRAY

type QdiskHook string

const (
	QdiskIngress QdiskHook = "ingress"
	QdiskEgress  QdiskHook = "egress"
)

func (m *Map) Name() string {
	name, err := C.bpf_map__name(m.bpfMap)
	if err != nil {
		return ""
	}
	return C.GoString(name)
}

func (m *Map) Type() int {
	mapType, err := C.bpf_map__type(m.bpfMap)
	if err != nil {
		return -1
	}
	return int(mapType)
}

func (m *Map) SetPinPath(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	err := C.bpf_map__set_pin_path(m.bpfMap, cPath)
	if err != 0 {
		return fmt.Errorf("pinning map failed %v", err)
	}
	return nil
}

// bpf_obj__open does not set errno. Errno is returned in the obj.
func OpenObject(filename string) (*Obj, error) {
	bpf.IncreaseLockedMemoryQuota()
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	obj := C.bpf_obj_open_load(cFilename)
	if obj.obj == nil {
		msg := "error opening program"
		if obj.errno != 0 {
			errno := syscall.Errno(-int64(obj.errno))
			msg = fmt.Sprintf("error opening program: %v", errno.Error())
		}
		return nil, fmt.Errorf(msg)
	}
	return &Obj{obj: obj.obj}, nil
}

func (o *Obj) Load() error {
	err := C.bpf_object__load(o.obj)
	if err != 0 {
		return fmt.Errorf("error loading object %v", err)
	}
	return nil
}

func (o *Obj) FirstMap() (*Map, error) {
	bpfMap, err := C.bpf_map__next(nil, o.obj)
	if bpfMap == nil || err != nil {
		return nil, fmt.Errorf("error getting first map %v", err)
	}
	return &Map{bpfMap: bpfMap, bpfObj: o.obj}, nil
}

func (m *Map) NextMap() (*Map, error) {
	bpfMap, err := C.bpf_map__next(m.bpfMap, m.bpfObj)
	if err != nil {
		return nil, fmt.Errorf("error getting next map %v", err)
	}
	if bpfMap == nil && err == nil {
		return nil, nil
	}
	return &Map{bpfMap: bpfMap, bpfObj: m.bpfObj}, nil
}

func (o *Obj) AttachClassifier(secName, ifName, hook string) (*TCOpts, error) {
	isIngress := 0
	cSecName := C.CString(secName)
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cSecName))
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return nil, err
	}

	if hook == string(QdiskIngress) {
		isIngress = 1
	}

	opts := C.bpf_tc_program_attach(o.obj, cSecName, C.int(ifIndex), C.int(isIngress))
	if opts.opts.prog_fd < 0 || opts.errno != 0 {
		return nil, fmt.Errorf("Error attaching tc program ")
	}
	return &TCOpts{opts: opts.opts}, nil
}

func CreateQDisc(ifName string) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return err
	}
	_, err = C.bpf_tc_create_qdisc(C.int(ifIndex))
	if err != nil {
		return fmt.Errorf("Error creating qdisc")
	}
	return nil
}

func RemoveQDisc(ifName string) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return err
	}
	_, err = C.bpf_tc_remove_qdisc(C.int(ifIndex))
	if err != nil {
		return fmt.Errorf("Error removing qdisc")
	}
	return nil
}

func (o *Obj) UpdateJumpMap(mapName, progName string, mapIndex int) error {
	cMapName := C.CString(mapName)
	cProgName := C.CString(progName)
	defer C.free(unsafe.Pointer(cMapName))
	defer C.free(unsafe.Pointer(cProgName))
	err := C.bpf_tc_update_jump_map(o.obj, cMapName, cProgName, C.int(mapIndex))
	if err != 0 {
		return fmt.Errorf("Error updating %s at index %d", mapName, mapIndex)
	}
	return nil
}

func GetProgID(ifaceName, hook string, opts *TCOpts) (int, error) {
	isIngress := 0
	cIfName := C.CString(ifaceName)
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return -1, err
	}
	if hook == "ingress" {
		isIngress = 1
	}
	progId := C.bpf_tc_query_iface(C.int(ifIndex), opts.opts, C.int(isIngress))
	if int(progId) < 0 {
		return -1, fmt.Errorf("Error querying interface %s", ifaceName)
	}
	return int(progId), nil
}

func (o *Obj) Close() error {
	if o.obj != nil {
		C.bpf_object__close(o.obj)
		o.obj = nil
		return nil
	}
	return fmt.Errorf("error: libbpf obj nil")
}
