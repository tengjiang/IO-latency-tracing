// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* Template by yanniszark in 2024 */
/* Adapted by tengjiang in 2024 */

// All linux kernel type definitions are in vmlinux.h
#include "vmlinux.h"
// BPF helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "iolatency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct request *); // key: pointer to BIO request
	__type(value, __u64); // time stamp
    __uint(max_entries, MAX_ENTRIES);
} starts SEC(".maps");

static struct hist initial_hist;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u8);
	__type(value, struct hist);
} hist SEC(".maps");


static __always_inline u64 log2(u32 v)
{
	u32 shift, r;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);

	return r;
}

static __always_inline u64 log2l(u64 v)
{
	u32 hi = v >> 32;

	if (hi)
		return log2(hi) + 32;
	else
		return log2(v);
}

static int __always_inline trace_rq_start(struct request *rq)
{
    u64 ts;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &rq, &ts, 0);
    return 0;
}

SEC("raw_tp/block_rq_issue")
int BPF_PROG(trace_block_rq_issue, struct request *rq)
{
    return trace_rq_start(rq);
}

SEC("raw_tp/block_rq_insert")
int BPF_PROG(trace_block_rq_insert, struct request *rq)
{
    return trace_rq_start(rq);
}

SEC("raw_tp/block_rq_complete")
int BPF_PROG(trace_block_rq_complete, struct request *rq)
{
    u64 slot, *tsp, ts;
    s64 delta;
    struct hist *histp;
    u8 zero;
    
    zero = 0;

    ts = bpf_ktime_get_ns();

    tsp = bpf_map_lookup_elem(&starts, &rq);
    if (!tsp)
        return 0;
    
    delta = (s64)(ts - *tsp);
    if (delta < 0)
		goto cleanup;

    histp = bpf_map_lookup_elem(&hist, &zero);

    if (!histp) {
		bpf_map_update_elem(&hist, &zero, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hist, &zero);
		if (!histp) {
            goto cleanup;
        }
	}

    delta /= 1000U;
    slot = log2l(delta);
	if (slot >= MAX_SLOTS)
	    slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
    
cleanup:
	bpf_map_delete_elem(&starts, &rq);
    return 0;
}