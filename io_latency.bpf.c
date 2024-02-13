// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* Template by yanniszark in 2024 */
/* Adapted by tengjiang in 2024 */

// All linux kernel type definitions are in vmlinux.h
#include "vmlinux.h"
// BPF helpers
#include <bpf/bpf_helpers.h>

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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, f64);
	__type(value, f64);
	__uint(max_entries, 500);  // most linux systems have 300-400 syscalls
} syscall_id_to_count SEC(".maps");

// Idea 2, with block IO request trace points
// void trace_block_rq_issue(struct request *rq)
// void trace_block_rq_complete(struct request *rq, blk_status_t error, unsigned int nr_bytes)¶
// trace_block_io_done(struct request *rq)¶


// SEC name is important! libbpf infers program type from it.
// See: https://docs.kernel.org/bpf/libbpf/program_types.html#program-types-and-elf
SEC("tracepoint")
int handle_tracepoint(void *ctx) {
    // bpf_get_current_pid_tgid is a helper function!
    int pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("BPF triggered from PID %d.\n", pid);

    return 0;
}

SEC("traceio")
int handle_traceio(void *ctx) {
    // bpf_get_current_pid_tgid is a helper function!
    int pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("BPF triggered from PID %d.\n", pid);

    return 0;
}