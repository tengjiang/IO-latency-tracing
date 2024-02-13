#ifndef __IO_LATENCY_H
#define __IO_LATENCY_H

#define MAX_SLOTS	27

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __IO_LATENCY_H */