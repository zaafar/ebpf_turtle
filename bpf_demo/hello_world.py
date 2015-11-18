#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./hello_world.py"

from bcc import BPF


# bpf program in restricted C language.
prog = """
int hello_world(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}
"""

b = BPF(text=prog)

# attaching hello_world function to sys_clone system call.
b.attach_kprobe(event="sys_clone", fn_name="hello_world")

# reading from /sys/kernel/debug/tracing/trace_pipe
b.trace_print(fmt="Program:{0} Message:{5}")
