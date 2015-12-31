#define TOTAL_VNFS 6 //Bridge +Router +Bridge + Patchpanel + rvm + transport_manager
#define CB_INDEX 0

struct ifc_info {
  u32 is_virtual;
  u32 dst_num;
  u32 prog_index;
};

//BPF TABLES TO CONTAIN ALL PROGRAMS INFO
BPF_TABLE("prog", u32, u32, vnf_prog, TOTAL_VNFS);

//Patchpannel table
BPF_TABLE("hash", u32, struct ifc_info, forwarder_vi, 1024);

int linker(struct __sk_buff *skb) {
  bpf_trace_printk("Hello, packet patch panel vnf\n");
  u32 pkt_vi = skb->cb[CB_INDEX];
  struct ifc_info *dst = forwarder_vi.lookup(&pkt_vi);

  if (dst) {
    skb->cb[CB_INDEX] = dst->dst_num;
    if (dst->is_virtual) {
      vnf_prog.call(skb, dst->prog_index);
    } else {
      u32 temp = bpf_redirect(dst->prog_index, 1 /*ingress*/);
      bpf_trace_printk("Hello, sending packet to bridge..%d, %d\n", dst->prog_index, temp);
    }
  }
  return 1;
}
