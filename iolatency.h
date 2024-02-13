#ifndef __IOLATENCY_H
#define __IOLATENCY_H

#define MAX_SLOTS	27

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __IOLATENCY_H */