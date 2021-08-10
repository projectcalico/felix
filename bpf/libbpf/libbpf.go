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

// #cgo CFLAGS: -I../../bpf-gpl/include/libbpf/src
// #include <stdlib.h>
// #include "libbpf_api.h"
import "C"

type Obj struct {
	obj *C.struct_bpf_object
}

type Link struct {
	link *C.struct_bpf_link
}

func OpenObject(filename string) (*Obj, error) {
	bpf.IncreaseLockedMemoryQuota()
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	obj := C.bpf_obj_open_load(cFilename)
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
