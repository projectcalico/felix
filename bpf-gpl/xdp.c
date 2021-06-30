#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>

#include "bpf.h"
#include "types.h"
#include "log.h"
#include "skb.h"
#include "routes.h"
#include "reasons.h"
#include "icmp.h"
#include "fib.h"
#include "parsing.h"
#include "failsafe.h"
#include "jump.h"

struct flow_tuple {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8 protocol;
};

struct bpf_map_def_extended SEC("maps") flowtracker = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_tuple),
	.value_size = sizeof(__u64),
	.max_entries = 32,
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy = MAP_PIN_GLOBAL,
#endif
};

SEC("prog")
static CALI_BPF_INLINE int calico_xdp(struct xdp_md *xdp_ctx) {

	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.xdp = xdp_ctx,
		.fwd = {
			.res = XDP_PASS, // or XDP_DROP?
			.reason = CALI_REASON_UNKNOWN,
		},
	};

	if (!ctx.state) {
		CALI_DEBUG("State map lookup failed: PASS\n");
		return XDP_PASS; // or XDP_DROP?
	}
	__builtin_memset(ctx.state, 0, sizeof(*ctx.state));

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		ctx.state->prog_start_time = bpf_ktime_get_ns();
	}

	// Packet is malformed or non an IPv4
	if (parse_packet_ip(&ctx)) {
		return ctx.fwd.res;
	}

	// no a TCP packet
	if (ctx.ip_header->protocol != IPPROTO_TCP)
		return XDP_PASS;
	
	struct flow_tuple flow = {};
	flow.protocol = ctx.ip_header->protocol;
	flow.saddr = ctx.ip_header->saddr;
	flow.daddr = ctx.ip_header->daddr;
	flow.sport = ctx.tcp_header->source;
	flow.dport = ctx.tcp_header->dest;
	
	__u64 new_counter = 1;
	__u64 *counter;
	
	counter = bpf_map_lookup_elem(&flowtracker, &flow);
	if (counter) {
		__sync_fetch_and_add(counter, 1);
	} else {
		bpf_map_update_elem(&flowtracker, &flow, &new_counter, BPF_ANY);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
