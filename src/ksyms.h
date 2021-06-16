/*
Code Taken From BCC Project's trace_helpers.h
https://github.com/iovisor/bcc/blob/master/libbpf-tools/trace_helpers.c
*/

#ifndef KSYMS_H
#define KSYMS_H
struct ksym {
	const char *name;
	unsigned long addr;
};

struct ksyms {
	struct ksym *syms;
	int syms_sz;
	int syms_cap;
	char *strs;
	int strs_sz;
	int strs_cap;
};

struct ksyms *ksyms__load(void);
void ksyms__free(struct ksyms *ksyms);
const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr);

#endif // KSYMS_H
