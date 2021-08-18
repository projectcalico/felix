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

type Link struct {
	link *C.struct_bpf_link
}

type TCOpts struct {
	opts C.struct_bpf_tc_opts
}

func OpenObject(filename, ifaceName, hook string) (*Obj, error) {
	bpf.IncreaseLockedMemoryQuota()
	cFilename := C.CString(filename)
	if hook == "ingress" {
		ifaceName = ifaceName + "_igr"
	} else {
		ifaceName = ifaceName + "_egr"
	}
	cIfacename := C.CString(ifaceName)
	defer C.free(unsafe.Pointer(cFilename))
	defer C.free(unsafe.Pointer(cIfacename))

	obj := C.bpf_obj_open_load(cFilename, cIfacename)
	if obj.obj == nil {
		msg := "error loading program"
		if obj.errno != 0 {
			errno := syscall.Errno(-int64(obj.errno))
			msg = fmt.Sprintf("error loading program: %v", errno.Error())
		}
		return nil, fmt.Errorf(msg)
	}
	return &Obj{obj: obj.obj}, nil
}

func (o *Obj) AttachKprobe(progName, fn string) (*Link, error) {
	cProgName := C.CString(progName)
	cFnName := C.CString(fn)
	defer C.free(unsafe.Pointer(cProgName))
	defer C.free(unsafe.Pointer(cFnName))
	link := C.bpf_program_attach_kprobe(o.obj, cProgName, cFnName)
	if link.link == nil {
		msg := "error attaching kprobe"
		if link.errno != 0 {
			errno := syscall.Errno(-int64(link.errno))
			msg = fmt.Sprintf("error attaching kprobe: %v", errno.Error())
		}
		return nil, fmt.Errorf(msg)
	}
	return &Link{link: link.link}, nil
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

func (l *Link) Close() error {
	if l.link != nil {
		err := C.bpf_link_destroy(l.link)
		if err != 0 {
			return fmt.Errorf("error destroying link: %v", err)
		}
		l.link = nil
		return nil
	}
	return fmt.Errorf("link nil")
}

func (o *Obj) Close() error {
	if o.obj != nil {
		C.bpf_object__close(o.obj)
		o.obj = nil
		return nil
	}
	return fmt.Errorf("error: libbpf obj nil")
}
