#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./ipfirewall.py"

from bcc import BPF
from pyroute2 import IPRoute, IPDB


def ip2bin(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


prog = """
#include <bcc/proto.h>
enum IP_ALLOW {
  IP=XXXXXXXXXX,
};

int incomming_handler(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  switch (ethernet->type) {
    case 0x0800: goto IP;
  }
IP: ;
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  if (ip->src == IP) {
      bpf_trace_printk("Allowing traffic from IP %d\\n", IP);
      return 0;
  }
  return 1;
}
"""


ipr = IPRoute()
ipdb = IPDB(nl=ipr)
ifc = ipdb.interfaces.eth0


prog.replace("XXXXXXXXXX",ip2bin("10.11.13.1"))

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

