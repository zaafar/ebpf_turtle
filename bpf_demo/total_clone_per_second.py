#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./total_clone_per_second.py"

from bcc import BPF
from time import sleep

# bpf program in restricted C language.
prog = """
BPF_TABLE("array", u32, u32, stats, 1);
int hello_world(void *ctx) {
  u32 key = 0, value = 0, *val;
  val = stats.lookup_or_init(&key, &value);
  lock_xadd(val, 1);
  return 0;
}
"""

b = BPF(text=prog)

# getting shared kernel map
stats_map = b.get_table("stats")

# attaching hello_world function to sys_clone system call.
b.attach_kprobe(event="sys_clone", fn_name="hello_world")

for x in range(0, 10):
  stats_map[ stats_map.Key(0) ] = stats_map.Leaf(0)
  sleep(1)
  print "Total sys_clone per second =", stats_map[ stats_map.Key(0) ].value;
