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
    struct bpf_link *links[3];
    int prog_fd;
    int time_interval;
    char *prog_names[] = {"trace_block_rq_issue", "trace_block_rq_insert", "trace_block_rq_complete"};

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

    // Attach BPF program, need to attach all 3 tracepoints
    for (int i = 0; i < 3; i++) {
        fprintf(stderr, "Attaching BPF program %s to tracepoint\n", prog_names[i]);
        prog = bpf_object__find_program_by_name(obj, prog_names[i]);
        if (libbpf_get_error(prog)) {
            fprintf(stderr, "ERROR: finding BPF program failed\n");
            return 1;
        }
        prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            fprintf(stderr, "ERROR: getting BPF program FD failed\n");
            return 1;
        }

        links[i] = bpf_program__attach(prog);

        if (libbpf_get_error(links[i])) {
            fprintf(stderr, "ERROR: Attaching BPF program to tracepoint failed\n");
            return 1;
        }
    }

    printf("BPF tracepoint program attached. Press ENTER to exit...\n");
    getchar();

    // Cleanup
    for (int i = 0; i < 3; i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);

    return 0;
}