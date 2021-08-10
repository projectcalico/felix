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

#include <libbpf.h>
#include <linux/limits.h>

#define MAX_ERRNO 4095
bool IS_ERR(const void *ptr) {
     if((long)ptr >= -MAX_ERRNO && (long)ptr < 0) {
         return true;
     }
     return false;
}

long ERR_VAL(const void *ptr) {
      return (long) ptr;
}

struct bpf_obj_wrapper {
	struct bpf_object *obj;
	int errno;
};

struct bpf_link_wrapper {
	struct bpf_link *link;
	int errno;
};

struct bpf_obj_wrapper bpf_obj_open_load(char *filename) {
	struct bpf_obj_wrapper obj;
	obj.obj = bpf_object__open(filename);
	obj.errno = 0;
	struct bpf_map *map;
	int err, len;
	char buf[PATH_MAX];
	char path[] = "/sys/fs/bpf/tc/globals/";

	if (obj.obj == NULL) {
		return obj;
	}
	if (IS_ERR(obj.obj)) {
		obj.errno = ERR_VAL(obj.obj);
		obj.obj = NULL;
		return obj;
	}
	bpf_object__for_each_map(map, obj.obj) {
		len = snprintf(buf, PATH_MAX, "%s/%s", path, bpf_map__name(map));
		if (len < 0) {
			obj.obj = NULL;
			return obj;
		}
		obj.errno = bpf_map__set_pin_path(map, buf);
		if (obj.errno) {
			obj.obj = NULL;
			return obj;
		}
	}
	obj.errno = bpf_object__load(obj.obj);

	if (obj.errno) {
		obj.obj = NULL;
		return obj;
	}
	return obj;
}

struct bpf_link_wrapper bpf_program_attach_kprobe(struct bpf_object *obj, char *progName, char *fn) {
	struct bpf_link_wrapper link;
	link.link = NULL;
	link.errno = 0;
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, progName);
	if (prog == NULL) {
		return link;
	}
	link.link = bpf_program__attach_kprobe(prog, false, fn);
	if (link.link == NULL) {
		return link;
	}
	if (IS_ERR(link.link)) {
		link.errno = ERR_VAL(link.link);
	}
	return link;
}

int bpf_link_destroy(struct bpf_link *link) {
	return bpf_link__destroy(link);
}

