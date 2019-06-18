// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <iproute2/bpf_elf.h>
#include <stdbool.h>

#include "../include/bpf.h"

struct prefilter_key {
	struct bpf_lpm_trie_key lpm;
	__u8 ip[4];
};

struct failsafe_key {
	__u8 protocol;
	__u16 port;
};

struct failsafe_value {
	__u8 dummy;
};

// calico_prefilter_v4 contains one entry per CIDR that should be dropped by
// the prefilter.
//
// Key: the CIDR, formatted for LPM lookup
// Value: reference count, used only by felix
struct bpf_elf_map calico_prefilter_v4 __section(ELF_SECTION_MAPS) = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct prefilter_key),
	.size_value	= sizeof(__u32),
	.max_elem	= 512000, // arbitrary
	.flags		= BPF_F_NO_PREALLOC,
};

// calico_failsafe_ports contains one entry per port/proto that we should NOT
// block even if there's a blacklist rule. This corresponds with the failsafe
// ports option in Felix and is populated by Felix at startup time.
//
// Key: the protocol and port
// Value: not used
struct bpf_elf_map calico_failsafe_ports __section(ELF_SECTION_MAPS) = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct failsafe_key),
	.size_value	= sizeof(struct failsafe_value),
	.max_elem	= 131070, // number of ports for TCP and UDP
	.flags		= BPF_F_NO_PREALLOC,
};

__section("pre-filter")
int xdp_enter(struct xdp_md *xdp)
{
	void *data = (void *)(__u64) xdp->data;
	void *data_end = (void *)(__u64) xdp->data_end;
	struct ethhdr *ethernet_header = data;
	struct iphdr *ip_header = data + sizeof(struct ethhdr);
	__u16 h_proto;

	if (ethernet_header + 1 > data_end) {
		return XDP_DROP;
	}

	h_proto = ethernet_header->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) { // filter IPv4
		struct prefilter_key key = {};
		__u32 *ref_count;

		if (ip_header + 1 > data_end) {
			return XDP_DROP;
		}

		__builtin_memcpy(&key.lpm.data, &ip_header->saddr, sizeof(key.ip));
		key.lpm.prefixlen = 32;
		ref_count = bpf_map_lookup_elem(&calico_prefilter_v4, &key);
		if (ref_count) { // maybe drop if source address in CIDR
			struct failsafe_key protocol_and_port = {};

			if (ip_header->protocol == IPPROTO_TCP) {
				struct tcphdr *tcp_header = (void *)(ip_header + 1);

				if (tcp_header + 1 > data_end) {
					return XDP_DROP;
				}

				protocol_and_port.port = bpf_ntohs(tcp_header->dest);
			} else if (ip_header->protocol == IPPROTO_UDP) {
				struct udphdr *udp_header = (void *)(ip_header + 1);

				if (udp_header + 1 > data_end) {
					return XDP_DROP;
				}

				protocol_and_port.port = bpf_ntohs(udp_header->dest);
			} else {
				return XDP_DROP;
			}

			protocol_and_port.protocol = ip_header->protocol;
			if (!bpf_map_lookup_elem(&calico_failsafe_ports, &protocol_and_port)) {
				return XDP_DROP; // but only drop if not in failsafe ports
			}
		}
	}

	return XDP_PASS;
}

char ____license[] __section("license")  = "Apache-2.0";
