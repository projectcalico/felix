// Project Calico BPF dataplane programs.
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#ifndef __CALI_POLICY_H__
#define __CALI_POLICY_H__

enum calico_policy_result {
	CALI_POL_NO_MATCH,
	CALI_POL_ALLOW,
	CALI_POL_DENY,
};

struct port_range {
       __u64 ip_set_id;
       __u16 min, max;
};

struct cidr {
       __be32 mask, addr;
};

// IP sets, all stored in one big map with a prefix to identify the set.

// WARNING: must be kept in sync with the definitions in bpf/polprog/pol_prog_builder.go.
// WARNING: must be kept in sync with the definitions in bpf/ipsets/map.go.
struct ip4_set_key {
	__u32 mask;
	__be64 set_id;
	__be32 addr;
	__u16 port;
	__u8 protocol;
	__u8 pad;
} __attribute__((packed));

union ip4_set_lpm_key {
	struct bpf_lpm_trie_key lpm;
	struct ip4_set_key ip;
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_ip_sets = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union ip4_set_lpm_key),
	.value_size     = sizeof(__u32),
	.max_entries    = 1024*1024,
//	.map_flags      = BPF_F_NO_PREALLOC,
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy        = MAP_PIN_GLOBAL,
#endif
};

#define RULE_START(id) \
	CALI_DEBUG("Rule " #id " \n");

#define RULE_END(id, action) \
	CALI_DEBUG("  MATCH -> " #action "\n"); \
	goto action; /* Reach here if the rule matched. */ \
	rule_no_match_ ## id: do {;} while (false)


#endif /* __CALI_POLICY_H__ */
