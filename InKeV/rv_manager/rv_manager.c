//*********************************************//
// TODO: This should be converted into a macro,
// or in a common ebpf header file
enum cb_index {
  VIRTUAL_INDEX = 0,
};

// ebpf table to contain info of next hop vnf.
// It will always be Patch Panel in our architecture.
BPF_TABLE("prog", u32, u32, next_hop, 1);

static void forward(struct __sk_buff *skb, u32 port_number) {
  skb->cb[0] = port_number;
  next_hop.call(skb, 0);
}
//*********************************************//


BPF_TABLE("hash", u32, u32, rvm_ifc2vi, 1024);
BPF_TABLE("hash", u32, u32, rvm_vi2ifc, 1024);

// Handle packets from (namespace outside) interface
int rvm_function_p2v(struct __sk_buff *skb) {
  u32 ifindex = skb->ifindex, *vi_num;
  vi_num = rvm_ifc2vi.lookup( &ifindex );
  if ( vi_num ) {
    forward(skb, *vi_num);
    return 1;
  }
  return 0;
}

// Handle packets from VNFs.
int rvm_function_v2p(struct __sk_buff *skb) {
  u32 vi_num = skb->cb[VIRTUAL_INDEX], *iface;
  iface = rvm_vi2ifc.lookup( &vi_num );
  if (iface) {
    bpf_clone_redirect(skb, *iface, 0/*egress*/);
    return 1;
  }
  return 0;
}
