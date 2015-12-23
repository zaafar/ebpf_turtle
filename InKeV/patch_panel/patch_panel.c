#define TOTAL_VNFS 6 //Bridge +Router +Bridge + Patchpanel + pvm + transport_manager

enum cb_index {
  VIRTUAL_INDEX = 0,
};

struct ifc_info {
  u32 dst_num;
  u32 prog_index;
};

//BPF TABLES TO CONTAIN ALL PROGRAMS INFO
BPF_TABLE("prog", u32, u32, vnf_prog, TOTAL_VNFS);

//Patchpannel table
BPF_TABLE("hash", u32, struct ifc_info, forwarder_vi, 1024);

int linker(struct __sk_buff *skb) {
  u32 pkt_vi = skb->cb[VIRTUAL_INDEX];
  struct ifc_info *dst = forwarder_vi.lookup(&pkt_vi);

  if (dst) {
    skb->cb[VIRTUAL_INDEX] = dst->dst_num;
    vnf_prog.call(skb, dst->prog_index);
  }
  return 1;
}
