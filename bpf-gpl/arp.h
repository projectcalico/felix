// Project Calico BPF dataplane programs.
// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

#ifndef __CALI_ARP_H__
#define __CALI_ARP_H__

#include "arp_types.h"
#include "types.h"
#include "log.h"

CALI_MAP(cali_v4_arp, 2, BPF_MAP_TYPE_LRU_HASH, struct arp_key, struct arp_value, 10000, 0, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE void arp_record_reverse(struct cali_tc_ctx *ctx)
{
	ctx->arpk.ip = ctx->ip_header->saddr;
	ctx->arpk.ifindex = ctx->skb->ifindex;

	/* We update the map straight with the packet data, eth header is
	 * dst:src but the value is src:dst so it flips it automatically
	 * when we use it on xmit.
	 */
	if (cali_v4_arp_update_elem(&ctx->arpk, ctx->eth, 0)) {
		CALI_INFO("ARP update for ifindex %d ip %xi failed\n", ctx->arpk.ifindex, bpf_ntohl(ctx->arpk.ip));
	} else {
		CALI_DEBUG("ARP update for ifindex %d ip %x\n", ctx->arpk.ifindex, bpf_ntohl(ctx->arpk.ip));
	}
}

#endif /* __CALI_ARP_H__ */
