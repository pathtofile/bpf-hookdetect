// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "hookdetect.skel.h"
#include "common_um.h"
#include "common.h"
#include "ksyms.h"

// Setup Argument stuff
static struct env {
    int pid_to_hide;
    int target_ppid;
    bool verbose;
} env;

const char *argp_program_version = "hookdetect 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"Hook Detect\n"
"\n"
"Detects kernel rootkits hooking syscalls\n"
"Syscalls checked: kill, getdents, getdents64\n"
"\n"
"USAGE: ./hookdetect [-t 1111] [-v]\n";

static const struct argp_option opts[] = {
    { "target-ppid", 't', "PPID", 0, "Optional Parent PID, will only check its children." },
    { "verbose", 'v', NULL, 0, "Verbose, print stack traces" },
    {},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 't':
        errno = 0;
        env.target_ppid = strtol(arg, NULL, 10);
        if (errno || env.target_ppid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'v':
        env.verbose = true;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};
static struct hookdetect_bpf *skel;
static struct ksyms *ksyms;

static void log_hooked_syscall(const struct event *e)
{
    char log[300];
    char* msg_next;
    switch (e->syscall_nr) {
        case SYS_getdents:
            sprintf(log, "sys_getdents");
            break;
        case SYS_getdents64:
            sprintf(log, "sys_getdents64");
            break;
        case SYS_kill:
            sprintf(log, "sys_kill");
            break;
        default:
            sprintf(log, "other syscall");
            break;
    }
    msg_next = &log[0] + strlen(log);
    sprintf(msg_next, " is hooked for PID %d (%s)", e->pid, e->comm);
    msg_next = &log[0] + strlen(log);
    if (e->with_stack_trace) {
        sprintf(msg_next, " - Real function called but data possibly altered");
    }
    else {
        sprintf(msg_next, " - Real function not called");
    }
    printf("%s\n", log);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->with_stack_trace) 
    {
        // Get stack traces
        __u64 stacks[MAX_STACK_DEPTH];
        __u64 stack;
        const struct ksym *ksym = NULL;
        int stack_i = 0;

        int ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.map_stack_traces), &e->stack_id, &stacks);
        if (ret < 0) {
            printf("Error finding stack trace\n");
            return 0;
        }

        if (env.verbose) {
                switch (e->syscall_nr) {
                    case SYS_getdents:
                        fprintf(stderr, "sys_getdents:\n");
                        break;
                    case SYS_getdents64:
                        fprintf(stderr, "sys_getdents64:\n");
                        break;
                    case SYS_kill:
                        fprintf(stderr, "sys_kill:\n");
                        break;
                    default:
                        fprintf(stderr, "other syscall:\n");
                        break;
                }
        }
        for (stack_i = 0; stack_i < MAX_STACK_DEPTH; stack_i++) {
            stack = stacks[stack_i];
            if (stack == 0) {
                break;
            }
            if (env.verbose) {
                // Lookup address to get function name
                ksym = ksyms__map_addr(ksyms, stack);
                printf("    0x%llx -> %s\n", stack, ksym ? ksym->name : "Unknown");
            }
        }
        // We expect to have only seen 2 stacks
        if (stack_i > 2) {
            log_hooked_syscall(e);
        }
    }
    else {
        // Missing syscall event
        log_hooked_syscall(e);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int err;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }

    // Do common setup
    if (!setup()) {
        exit(1);
    }

    ksyms = ksyms__load();
    if (!ksyms) {
        fprintf(stderr, "failed to load kallsyms\n");
        return 0;
    }

    // Open BPF application 
    skel = hookdetect_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Set target ppid
    skel->rodata->target_ppid = env.target_ppid;

    // Verify and load program
    err = hookdetect_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Attach tracepoint handler 
    err = hookdetect_bpf__attach( skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started!\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }
cleanup:
    hookdetect_bpf__destroy( skel);
    return -err;
}
