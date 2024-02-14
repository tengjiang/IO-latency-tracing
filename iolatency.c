#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "iolatency.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })


static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

static void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
	int stars_max = 40, idx_max = -1;
	unsigned int val, val_max = 0;
	unsigned long long low, high;
	int stars, width, i;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
		idx_max <= 32 ? 19 : 29, val_type);

	if (idx_max <= 32)
		stars = stars_max;
	else
		stars = stars_max / 2;

	for (i = 0; i <= idx_max; i++) {
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		val = vals[i];
		width = idx_max <= 32 ? 10 : 20;
		printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
		print_stars(val, val_max, stars);
		printf("|\n");
	}
}

int main(int argc, char *argv[]) {
    
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *links[3];
    int prog_fd;
    int time_interval;
    char *prog_names[] = {"trace_block_rq_issue", "trace_block_rq_insert", "trace_block_rq_complete"};
    __u8 zero = 0;

    // Check for input
    if (argc != 2) {
        fprintf(stderr, "Usage: %s [print time interval]\n", argv[0]);
        return EXIT_FAILURE;
    }
    time_interval = atoi(argv[1]);

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("iolatency.bpf.o", NULL);
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

    struct bpf_map *hist_map = bpf_object__find_map_by_name(obj, "hist");
    if (libbpf_get_error(hist_map)) {
        fprintf(stderr, "ERROR: finding BPF maps failed\n");
        return 1;
    }
    int map_fd = bpf_map__fd(hist_map);

    struct hist hist;
    int err;

    printf("BPF tracepoint program attached and maps found. Start printing histogram every %d sec.\n", time_interval);
    
    while (1) {
        sleep(time_interval);
        err = bpf_map_lookup_elem(map_fd, &zero, &hist);
        if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			break;
		}

        print_log2_hist(hist.slots, MAX_SLOTS, "usecs");

        err = bpf_map_delete_elem(map_fd, &zero);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			break;
		}
    }

    // Cleanup
    for (int i = 0; i < 3; i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);

    return 0;
}