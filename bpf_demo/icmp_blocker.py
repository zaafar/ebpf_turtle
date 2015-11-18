#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./icmp_blocker.py"

from bcc import BPF
from pyroute2 import IPRoute, IPDB


prog = """
#include <bcc/proto.h>

int incomming_handler(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  switch (ethernet->type) {
    case 0x0800: goto IP;
  }
IP: ;
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  switch (ip->nextp) {
    
    case 0x01:
      bpf_trace_printk("Dropping ICMP packets\\n");
      return 1;
  }
  return 0;
}
"""


ipr = IPRoute()
ipdb = IPDB(nl=ipr)
ifc = ipdb.interfaces.eth0

b = BPF(text=prog)
fun_incomming = b.load_func("incomming_handler", BPF.SCHED_CLS)
ipr.tc("add", "ingress", ifc.index, "ffff:")
ipr.tc("add-filter", "bpf", ifc.index, ":1", fd=fun_incomming.fd,
      name=fun_incomming.name, parent="ffff:", action="drop", classid=1)

try:
  print "All Ready..."
  # reading from /sys/kernel/debug/tracing/trace_pipe
  b.trace_print()
except KeyboardInterrupt:
  print "Ending Demo..."
finally:
  ipr.tc("del", "ingress", ifc.index, "ffff:")

