# BPF-HookDetect
Detect Kernel Rootkits hooking syscalls

- [Overview](#Overview)
- [Details](#Details)
- [To Build](#Build)
- [To Run](#Run)
- [Example Test](#Example-Test)
- [Resources](#Resources)
# Overview
Kernel Rootkits such as [Diamorphine](https://github.com/m0nad/Diamorphine) hook various syscall functions
so they can either:
- Hide files and processes from usermode applications, by altering the data returned from the Kernel
- Facilitate a covert channel from usermode-kernel to trigger actions such as priliege escallation

This project attempts to detect this syscall hooking using eBPF, and it's ability to get kernel stack traces.
`HookDetect` monitors the following syscalls:
- kill
  - Used to send signals to other processes
- getdents and getdents64
  - Used to list files and folders

`HookDetect` will check every use of these syscalls to check two things:
- How many stack frames are there between the initial kernel entrypoint and the actual syscall function
  - This detects when a hook interposes on the function to alter it's return data
- After the kernel detected the processes making a syscall, was the read function actually called?
  - This detect for the covert-channel uses where the real syscall is not actually run

# Details
For more details, see this blog: [Detecting kernel hooking using eBPF](https://blog.tofile.dev)

This code has been tested on:
- Ubuntu 21.04, Kernel 5.11.0-17
- RHEL 7.6, Kernel 3.10.0-957

# Build
To use pre-build binaries, grab them from the [Releases](https://github.com/pathtofile/bpf-hookdetect/releases) page.

To build from source, do the following:

## Dependecies
As this code makes use of CO-RE, it requires a recent version of Linux that has BTF Type information.
See [these notes in the libbpf README](https://github.com/libbpf/libbpf/tree/master#bpf-co-re-compile-once--run-everywhere)
for more information. For example Ubuntu requries `Ubuntu 20.10`+.

To build it requires these dependecies:
- zlib
- libelf
- libbfd
- clang 11
- make

On Ubuntu these can be installed by
```bash
sudo apt install build-essential clang-11 libelf-dev zlib1g-dev libbfd-dev libcap-dev libfd-dev
```

## Build
To Build from source, recusivly clone the respository the run `make` in the `src` directory to build:
```bash
git clone --recusrive https://github.com/pathtofile/bpf-hookdetect.git
cd bpf-hookdetect/src
make
```
The binaries will built into `bpf-hookdetect/src/bin`.


# Run
To run, run the `hookdetect` binary as root. If the program detects a function was hooked, it will print the syscall name,
along with the process and PID:
```bash
$> sudo ./bpf-hookdetect/src/bin/hookdetect
sys_getdents64 is hooked for PID 2584743 (ls) - Real function called but data possibly altered
sys_kill is hooked for PID 2584087 (bash) - Real function not called
```

# Example Test
To test, download, make, and install the [Diamorphine](https://github.com/m0nad/Diamorphine) rootkit.
Once rootkit is installed, start `hookdetect` and run:
```bash
# Sending signal 63 is intercepted by Diamorphine, and real syscall function is not called
kill -63 0

# But when sending other signals the real function is called
kill -s 23 $$
```

# Resources
The project's skeleton is adapted from [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap/)

The code to convert stack addresses to function names is taken from the [BCC Project](https://github.com/iovisor/bcc/blob/master/libbpf-tools/trace_helpers.c)
