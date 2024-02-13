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

#include "io_latency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


// Idea 1, with open and close

// syscall_enter_open, syscall_exit_open
// syscall_enter_openat, syscall_exit_openat
// syscall_enter_openat2, syscall_exit_openat2
// Todo: 1. Which task opens which file 2. map it to interval and count it
// Use a map to save the opened time of a fd (open/openat)
// Use a map to save the count of each interval (key is the left of each interval) [l, r)
// Upon closing, write the IO time to the second map

// Map of type hash (essentially a key-value store)
// Key: fd number
// Value: time when open/openat was called

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
// 	__type(key, f64);
// 	__type(value, f64);
// 	__uint(max_entries, 500);  // most linux systems have 300-400 syscalls
// } syscall_id_to_count SEC(".maps");

// Idea 2, with block IO request trace points
// void trace_block_rq_issue(struct request *rq)
// void trace_block_rq_complete(struct request *rq, blk_status_t error, unsigned int nr_bytes)¶
// trace_block_io_done(struct request *rq)¶


// SEC name is important! libbpf infers program type from it.
// See: https://docs.kernel.org/bpf/libbpf/program_types.html#program-types-and-elf

// SEC name inspired by: https://github.com/bpftrace/bpftrace/blob/master/docs/tutorial_one_liners.md

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
    // int pid = bpf_get_current_pid_tgid() >> 32; 
    // bpf_printk("BPF triggered from PID %d. rq issue\n", pid);
    return trace_rq_start(rq);
}

SEC("raw_tp/block_rq_insert")
int BPF_PROG(trace_block_rq_insert, struct request *rq)
{
    // int pid = bpf_get_current_pid_tgid() >> 32; 
    // bpf_printk("BPF triggered from PID %d. rq insert\n", pid);
    return trace_rq_start(rq);
    
}

SEC("raw_tp/block_rq_complete")
int BPF_PROG(trace_block_rq_complete, struct request *rq)
{
    // int pid = bpf_get_current_pid_tgid() >> 32; 
    // bpf_printk("BPF triggered from PID %d. rq complete\n", pid);
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
		if (!histp)
			goto cleanup;
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