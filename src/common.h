// SPDX-License-Identifier: BSD-3-Clause
#ifndef BPF_HOOKDETECT_COMMON_H
#define BPF_HOOKDETECT_COMMON_H
#include <stdbool.h>

// These are used by a number of
// different programs to sync eBPF Tail Call
// login between user space and kernel
#define PROG_01 1
#define PROG_02 2

// Simple message structure to get events from eBPF Programs
// in the kernel to user spcae
#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 10
struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool with_stack_trace;
    unsigned long stack_id;
    unsigned long syscall_nr;
};

#endif  // BPF_HOOKDETECT_COMMON_H