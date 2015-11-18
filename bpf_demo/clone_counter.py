#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./clone_counter.py"

from bcc import BPF


# bpf program in restricted C language.
prog = """
BPF_TABLE("array", u32, u32, stats, 1);
int hello_world(void *ctx) {
  u32 key = 0, value = 0, *val;
  val = stats.lookup_or_init(&key, &value);
  (*val)++;
  bpf_trace_printk("total fork syscall:%d\\n", *val);
  return 0;
}
"""

b = BPF(text=prog)

# attaching hello_world function to sys_clone system call.
b.attach_kprobe(event="sys_clone", fn_name="hello_world")

# reading from /sys/kernel/debug/tracing/trace_pipe
b.trace_print()
