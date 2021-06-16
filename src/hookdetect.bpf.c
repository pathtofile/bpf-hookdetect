// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <sys/syscall.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Optional Target Parent PID
const volatile int target_ppid = 0;

// Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Maps to tack threads
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, unsigned long);
} map_enter_raw SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, size_t);
} map_enter_syscall SEC(".maps");

// Map to hold stack trace
struct bpf_map_def SEC("maps") map_stack_traces = {
  .type = BPF_MAP_TYPE_STACK_TRACE,
  .key_size = sizeof(u32),
  .value_size = sizeof(size_t) * MAX_STACK_DEPTH,
  .max_entries = 8192,
};

// -------------------
// Syscall Listing vvv
static inline void trace_syscall(unsigned long long *ctx, unsigned long syscall_nr);
const unsigned long syscalls[] = {
    SYS_kill,
    SYS_getdents64,
};
const int syscalls_count = (sizeof(syscalls) / sizeof(const unsigned long));

SEC("kprobe/__x64_sys_kill")
int BPF_PROG(sys_kill, const struct pt_regs *regs)
{
    trace_syscall(ctx, SYS_kill);
    return 0;
}
SEC("kprobe/__x64_sys_getdents64")
int BPF_PROG(sys_getdents64, const struct pt_regs *regs)
{
    trace_syscall(ctx, SYS_getdents64);
    return 0;
}
SEC("kprobe/__x64_sys_getdents")
int BPF_PROG(sys_getdents, const struct pt_regs *regs)
{
    trace_syscall(ctx, SYS_getdents);
    return 0;
}
// Syscall Listing ^^^
// -------------------

static inline void trace_syscall(unsigned long long *ctx, unsigned long syscall_nr)
{
    // if target_ppid is 0 then we target all pids
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid && pid != target_ppid) {
            return;
        }
    }

    // Log event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->pid = pid;
        e->syscall_nr = syscall_nr;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));

        // Walk stack
        // Skip the first 3 stacks as these are after the syscall
        e->with_stack_trace = true;
        // stack_skip = 3 & BPF_F_SKIP_FIELD_MASK;
        e->stack_id = bpf_get_stackid(ctx, &map_stack_traces, 0);
        if (e->stack_id < 0) {
             bpf_printk("Failed to get stack %d", e->stack_id);
             e->stack_id = 0;
        }

        bpf_ringbuf_submit(e, 0);
    }

    // Also update map to track that we did actually run the syscall
    bpf_map_update_elem(&map_enter_syscall, &pid_tgid, &pid_tgid, BPF_ANY);
}

SEC("raw_tracepoint/sys_enter")
int bpf_test3(struct bpf_raw_tracepoint_args *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid && pid != target_ppid) {
            return 0;
        }
    }

    // Only run if one of the syscalls we're monitoring
    unsigned long syscall_nr = ctx->args[1];
    unsigned long syscall_check;
    bool found = false;
    for (int i = 0; i < syscalls_count; i++) {
        syscall_check = syscalls[i];
        if (syscall_check == syscall_nr) {
            // foind
            found = true;
            break;
        }
    }
    if (!found) {
        return 0;
    }

    // Update raw map
    bpf_map_update_elem(&map_enter_raw, &pid_tgid, &syscall_nr, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int bpf_test4(struct bpf_raw_tracepoint_args *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    // Check this is the exit to an entry call we're tacking
    unsigned long *check_syscall = bpf_map_lookup_elem(&map_enter_raw, &pid_tgid);
    if (check_syscall == 0) {
        return 0;
    }
    unsigned long syscall_nr = *check_syscall;

    // Check we entered actual syscall
    size_t *check = bpf_map_lookup_elem(&map_enter_syscall, &pid_tgid);
    if (check != 0) {
        // Syscall was called, all is normal
        bpf_map_delete_elem(&map_enter_syscall, &pid_tgid);
        bpf_map_delete_elem(&map_enter_raw, &pid_tgid);
        return 0;
    }

    // Syscall wasn't called! log event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->pid = pid;
        e->syscall_nr = syscall_nr;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));

        // We don't care about the stack
        e->with_stack_trace = false;
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&map_enter_raw, &pid_tgid);
    return 0;
}
