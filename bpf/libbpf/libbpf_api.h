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

#include "libbpf.h"
#include <linux/limits.h>
#include <net/if.h>
#include <bpf.h>
#include <stdlib.h>
#include <errno.h>

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

struct bpf_object* bpf_obj_open(char *filename) {
	errno = 0;
	struct bpf_object *obj;
	obj = bpf_object__open(filename);
	if (IS_ERR(obj)) {
		errno = ERR_VAL(obj);
		obj = NULL;
	}
	return obj;
}

void bpf_obj_load(struct bpf_object *obj) {
	errno = bpf_object__load(obj);
	return;
}

struct bpf_tc_opts bpf_tc_program_attach (struct bpf_object *obj, char *secName, int ifIndex, int isIngress) {
	errno = 0;
	struct bpf_tc_opts opts;

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach);

	if (isIngress) {
		hook.attach_point = BPF_TC_INGRESS;
	}

	attach.prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, secName));
	if (attach.prog_fd < 0) {
		errno = attach.prog_fd;
		return opts;
	}
	hook.ifindex = ifIndex;
	errno = bpf_tc_attach(&hook, &attach);
	memcpy (&opts, &attach, sizeof(struct bpf_tc_opts));
	return opts;
}

int bpf_tc_query_iface (int ifIndex, struct bpf_tc_opts opts, int isIngress) {
	errno = 0;

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	if (isIngress) {
		hook.attach_point = BPF_TC_INGRESS;
	}
	hook.ifindex = ifIndex;
	opts.prog_fd = opts.prog_id = opts.flags = 0;
	errno = bpf_tc_query(&hook, &opts);
	return opts.prog_id;
}

void bpf_tc_create_qdisc (int ifIndex) {
	errno = 0;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
	hook.ifindex = ifIndex;
	errno = bpf_tc_hook_create(&hook);
	return;
}

void bpf_tc_remove_qdisc (int ifIndex) {
        errno = 0;
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS);
        hook.ifindex = ifIndex;
        errno = bpf_tc_hook_destroy(&hook);
        return;
}

int bpf_tc_update_jump_map(struct bpf_object *obj, char* mapName, char *progName, int progIndex) {
	errno = 0;
	int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, progName));
	if (prog_fd < 0) {
		errno = prog_fd;
		return prog_fd;
	}
	int map_fd = bpf_object__find_map_fd_by_name(obj, mapName);
	if (map_fd < 0) {
		errno = map_fd;
		return map_fd;
	}
	return bpf_map_update_elem(map_fd, &progIndex, &prog_fd, 0);
}

