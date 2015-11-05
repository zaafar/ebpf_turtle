// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

enum cb_index {
  CB_VI = 0,
};

enum next_hop {
  BRIDGE = 1,
}

//BPF TABLES TO CONTAIN ALL PROGRAMS INFO
BPF_TABLE("prog", u32, u32, vnf_prog, TOTAL_VNFS);

//PEM BPF TABLES
BPF_TABLE("hash", u32, u32, rvm_ifc2vi, TOTAL_HOSTS);
BPF_TABLE("hash", u32, u32, rvm_vi2ifc, TOTAL_HOSTS);

// Handle packets from (namespace outside) interface
int rvm_function_p2v(struct __sk_buff *skb) {
  u32 ifindex = skb->ifindex, *vi_num;

  // change from physical interface to virtual interface
  // add it in the packet skb buffer.
  vi_num = rvm_ifc2vi.lookup( &ifindex );
  if (vi_num)
    skb->cb[CB_VI] = *vi_num;

  // pass the packet to next hop for further processing.
  vnf_prog.call(skb, BRIDGE);
  return 0;
}

// Handle packets from virtual network functions.
int rvm_function_v2p(struct __sk_buff *skb) {
  u32 vi_num = skb->cb[CB_VI], *iface;

  iface = rvm_vi2ifc.lookup( &vi_num );

  // pass the packet to a real interface for further processing.
  if (iface)
    bpf_clone_redirect(skb, iface, 0/*egress*/);
  return 0;
}
