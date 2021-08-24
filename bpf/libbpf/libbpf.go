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
	"syscall"
	"unsafe"

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
	name string
	mtype int
}

const MapTypeProgrArray = C.BPF_MAP_TYPE_PROG_ARRAY

func (m *Map) Name() string {
	return m.name
}

func (m *Map) Type() int {
	return m.mtype
}

func (m *Map) SetPinPath(obj *Obj, path string) error {
	cPath := C.CString(path)
	cMapName := C.CString(m.Name())
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cMapName))
	err := C.bpf_pin_map(obj.obj, cMapName, cPath)
	if err != 0 {
		return fmt.Errorf("pinning map failed %v", err)
	}
	return nil
}

func OpenObject(filename string) (*Obj, error) {
	bpf.IncreaseLockedMemoryQuota()
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	obj := C.bpf_obj_open(cFilename)
	if obj.obj == nil {
		msg := "error opening object"
		if obj.errno != 0 {
			errno := syscall.Errno(-int64(obj.errno))
			msg = fmt.Sprintf("error opening object: %v", errno.Error())
		}
		return nil, fmt.Errorf(msg)
	}
	return &Obj{obj: obj.obj}, nil
}

func (o *Obj) Load() error {
	err := C.bpf_obj_load(o.obj)
	if err != 0 {
		return fmt.Errorf("error loading object %v", err)
	}
	return nil
}

func (o *Obj) Maps() ([]Map, error) {
	var list[]Map
	data := C.getMaps(o.obj)
	length := int(C.numMaps(o.obj))
	if data != nil {
		slice := (*[1 << 28]C.struct_bpf_map_data)(unsafe.Pointer(data))[:length:length]
		for _, val := range slice {
			d := Map{name: C.GoString(val.name), mtype: int(val.mtype)}
			list = append(list, d)
		}
		return list, nil
	}
	return nil, fmt.Errorf("error getting maps from object")
}

func (o *Obj) AttachClassifier(secName, ifName, hook string) (*TCOpts, error) {
	isIngress := 0
	cSecName := C.CString(secName)
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cSecName))
	defer C.free(unsafe.Pointer(cIfName))
	if hook == "ingress" {
		isIngress = 1
	}
	opts := C.bpf_tc_program_attach(o.obj, cSecName, cIfName, C.int(isIngress))
	if opts.opts.prog_fd < 0 || opts.errno != 0 {
		return nil, fmt.Errorf("Error attaching tc program ")
	}
	return &TCOpts{opts: opts.opts}, nil
}

func CreateQDisc(ifName string) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))
	err := C.bpf_tc_create_qdisc(cIfName)
	if err != 0 {
		return fmt.Errorf("Error creating qdisc")
	}
	return nil
}

func RemoveQDisc(ifName string) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))
	err := C.bpf_tc_remove_qdisc(cIfName)
	if err != 0 {
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
	if hook == "ingress" {
		isIngress = 1
	}
	progId := C.bpf_tc_query_iface(cIfName, opts.opts, C.int(isIngress))
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
