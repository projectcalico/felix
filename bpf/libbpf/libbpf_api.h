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

struct bpf_tc_wrapper {
	struct bpf_tc_opts opts;
	int errno;
};

struct bpf_map_data {
	char *name;
	int mtype;
};

struct bpf_obj_wrapper bpf_obj_open(char *filename) {
	struct bpf_obj_wrapper obj;
	obj.obj = bpf_object__open(filename);
	obj.errno = 0;

	if (IS_ERR(obj.obj)) {
		obj.errno = ERR_VAL(obj.obj);
		obj.obj = NULL;
	}
	return obj;
}

int bpf_obj_load(struct bpf_object *obj) {
	return bpf_object__load(obj);
}

int numMaps(struct bpf_object *obj) {
	int count = 0;
	struct bpf_map *map;
	bpf_object__for_each_map(map, obj) {
		count++;
	}
	return count;
}

struct bpf_map_data* getMaps(struct bpf_object *obj) {
	int mapCount = numMaps(obj);
	struct bpf_map *map;
	const char *temp;
	int index = 0;

	if (!mapCount) {
		return NULL;
	}
	struct bpf_map_data *mapData = (struct bpf_map_data*)calloc(mapCount, sizeof(struct bpf_map_data));
	if (!mapData) {
		return NULL;
	}
	bpf_object__for_each_map(map, obj) {
		if (!map) {
			continue;
		}
		mapData[index].name = (char*)calloc(BPF_OBJ_NAME_LEN, sizeof(char));
		if (!mapData[index].name) {
			continue;
		}
		temp = bpf_map__name(map);
		strncpy(mapData[index].name, temp, BPF_OBJ_NAME_LEN);
		mapData[index++].mtype = bpf_map__type(map);
	}
	return mapData;
}

int bpf_pin_map(struct bpf_object *obj, char *mapName, char *pinPath) {
	struct bpf_map *map = bpf_object__find_map_by_name(obj, mapName);
	if (!map) {
		return -1;
	}
	return bpf_map__set_pin_path(map, pinPath);
}

struct bpf_tc_wrapper bpf_tc_program_attach (struct bpf_object *obj, char *secName, char *ifName, int isIngress) {
	int ifIndex = if_nametoindex(ifName);
	int err = 0;
	struct bpf_tc_wrapper tc;
	tc.errno = 0;

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach);

	if (isIngress) {
		hook.attach_point = BPF_TC_INGRESS;
	}

	attach.prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, secName));
	if (attach.prog_fd < 0) {
		tc.opts.prog_fd = attach.prog_fd;
		return tc;
	}
	hook.ifindex = ifIndex;
	tc.errno = bpf_tc_attach(&hook, &attach);
	memcpy (&tc.opts, &attach, sizeof(struct bpf_tc_opts));
	return tc;
}

int bpf_tc_query_iface (char *ifName, struct bpf_tc_opts opts, int isIngress) {
	int ifIndex = if_nametoindex(ifName);
	int err = 0;

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	if (isIngress) {
		hook.attach_point = BPF_TC_INGRESS;
	}
	hook.ifindex = ifIndex;
	opts.prog_fd = opts.prog_id = opts.flags = 0;
	err = bpf_tc_query(&hook, &opts);
	if (err) {
		return err;
	}
	return opts.prog_id;
}

int bpf_tc_create_qdisc (char *ifName) {
	int ifIndex = if_nametoindex(ifName);
	int err = 0;

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
	hook.ifindex = ifIndex;
	err = bpf_tc_hook_create(&hook);
	return err;
}

int bpf_tc_remove_qdisc (char *ifName) {
        int ifIndex = if_nametoindex(ifName);
        int err = 0;

        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS);
        hook.ifindex = ifIndex;
        err = bpf_tc_hook_destroy(&hook);
        return err;
}

int bpf_tc_update_jump_map(struct bpf_object *obj, char* mapName, char *progName, int progIndex) {
	int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, progName));
	if (prog_fd < 0) {
		return -1;
	}
	int map_fd = bpf_object__find_map_fd_by_name(obj, mapName);
	if (map_fd < 0) {
		return -1;
	}
	return bpf_map_update_elem(map_fd, &progIndex, &prog_fd, 0);
}

