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

#include "bpf.h"
#include "xdp.c"

static CALI_BPF_INLINE int calico_unittest_entry (struct cali_tc_ctx *ctx);

// Entry point for XDP unit tests
__attribute__((section("calico_unittest"))) int unittest(struct xdp_md *xdp)
{
	struct cali_tc_ctx ctx = {
		.xdp = xdp,
	};
	return calico_unittest_entry(&ctx);
}
