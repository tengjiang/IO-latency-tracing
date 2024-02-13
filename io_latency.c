#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "io_latency.h"

int main(int argc, char *argv[]) {
    
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int prog_fd;
    int time_interval;

    // Check for input
    if (argc != 2) {
        fprintf(stderr, "Usage: %s [print time interval]\n", argv[0]);
        return EXIT_FAILURE;
    }
    time_interval = atoi(argv[1]);

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("io_latency.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // Load BPF program
    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // Attach BPF program
    fprintf(stderr, "Attaching BPF program to tracepoint\n");
    prog = bpf_object__find_program_by_name(obj, "trace_block_rq_issue");
    if (libbpf_get_error(prog)) {
        fprintf(stderr, "ERROR: finding BPF program failed\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: getting BPF program FD failed\n");
        return 1;
    }
    // Check it out at: /sys/kernel/debug/tracing/events/block/block_rq_issue
    // link = bpf_program__attach_tracepoint(prog, "block", "block_rq_issue");
    // link = bpf_program__attach_raw_tracepoint(prog, "block_rq_issue");
    link = bpf_program__attach(prog);

    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: Attaching BPF program to tracepoint failed\n");
        return 1;
    }

    printf("BPF tracepoint program attached. Press ENTER to exit...\n");
    getchar();

    // Cleanup
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}


// #include <bpf/bpf.h>
// #include <bpf/libbpf.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <sys/sysinfo.h>
// #include <unistd.h>

// __u64 prev_syscall_counts[500];
// __u64 syscall_counts[500];

// int get_cpu_count() { return get_nprocs(); }

// __u64 roundup(__u64 num_to_round, __u64 multiple) {
//     return ((num_to_round + multiple - 1) / multiple) * multiple;
// }

// int main() {
//     struct bpf_object *obj;
//     struct bpf_program *prog;
//     struct bpf_link *link;
//     int prog_fd;

//     // Load and verify BPF application
//     fprintf(stderr, "Loading BPF code in memory\n");
//     obj = bpf_object__open_file("syscount.bpf.o", NULL);
//     if (libbpf_get_error(obj)) {
//         fprintf(stderr, "ERROR: opening BPF object file failed\n");
//         return 1;
//     }

//     // Load BPF program
//     fprintf(stderr, "Loading and verifying the code in the kernel\n");
//     if (bpf_object__load(obj)) {
//         fprintf(stderr, "ERROR: loading BPF object file failed\n");
//         return 1;
//     }

//     // Attach BPF program
//     fprintf(stderr, "Attaching BPF program to tracepoint\n");
//     prog = bpf_object__find_program_by_name(obj, "syscount");
//     if (libbpf_get_error(prog)) {
//         fprintf(stderr, "ERROR: finding BPF program failed\n");
//         return 1;
//     }
//     prog_fd = bpf_program__fd(prog);
//     if (prog_fd < 0) {
//         fprintf(stderr, "ERROR: getting BPF program FD failed\n");
//         return 1;
//     }
//     // Check it out at: /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter
//     link = bpf_program__attach_tracepoint(prog, "raw_syscalls", "sys_enter");

//     if (libbpf_get_error(link)) {
//         fprintf(stderr, "ERROR: Attaching BPF program to tracepoint failed\n");
//         return 1;
//     }

//     // Get syscall_id_to_count map
//     struct bpf_map *map;
//     map = bpf_object__find_map_by_name(obj, "syscall_id_to_count");
//     if (libbpf_get_error(map)) {
//         fprintf(stderr, "ERROR: finding BPF map failed\n");
//         return 1;
//     }

//     // Initialize total counts
//     for (int i = 0; i < 500; i++) {
//         prev_syscall_counts[i] = 0;
//     }
//     int map_fd = bpf_map__fd(map);
//     int num_cpus = get_cpu_count();
//     __u64 *values = (__u64 *)malloc(roundup(sizeof(__u64), 8) * num_cpus);
//     // For each CPU, iterate through map keys
//     // First, get the number of CPUs in the system
//     while (1) {
//         sleep(5);
//         // Gather values
//         __u64 *curr_key = NULL;
//         __u64 next_key;
//         while (bpf_map_get_next_key(map_fd, curr_key, &next_key) == 0) {
//             printf("Key: %llu\n", next_key);
//             // Get value
//             // This kernel
//             bpf_map_lookup_elem(map_fd, &next_key, values);
//             // Add to total
//             __u64 new_total = 0;
//             for (int i = 0; i < num_cpus; i++) {
//                 new_total += values[i];
//             }
//             syscall_counts[next_key] = new_total - prev_syscall_counts[next_key];
//             prev_syscall_counts[next_key] = new_total;
//             // Update key
//             curr_key = &next_key;
//         }
//         // Print results
//         printf("START: Syscall counts:\n");
//         for (int i = 0; i < 500; i++) {
//             if (syscall_counts[i] > 0) {
//                 printf("%s: %llu\n", syscall_id_to_name[i],
//                        syscall_counts[i]);
//             }
//         }
//         printf("END: Syscall counts\n\n");
//     }

//     // Cleanup
//     free(values);
//     bpf_link__destroy(link);
//     bpf_object__close(obj);

//     return 0;
// }