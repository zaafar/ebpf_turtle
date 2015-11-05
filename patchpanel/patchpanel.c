#define TOTAL_VNFS 5 //Bridge +Router +Bridge + Patchpanel + pvm

enum default_vnf {
  PATCH_PANEL = 0,
  PVM,
};

enum cb_index {
  CB_VI = 0,
};

struct ifc_info {
  bool isVirtual;
  u32 dst_num;
  u32 prog_index;
  int pad;
};

//BPF TABLES TO CONTAIN ALL PROGRAMS INFO
BPF_TABLE("prog", u32, u32, vnf_prog, TOTAL_VNFS);

//Patchpannel table
BPF_TABLE("hash", u32, struct ifc_info, forwarder_vi, 1024);

int patch_panel_function(struct __sk_buff *skb) {
  u32 pkt_vi = 0;
  struct ifc_info *dst;

  pkt_vi = skb->cb[CB_VI];
  dst = forwarder_vi.lookup(&pkt_vi);

  if (dst) {
    if (dst->isVirtual) {
      skb->cb[CB_VI] = dst->dst_num;
      vnf_prog.call(skb, dst->prog_index);
    } else {
      bpf_clone_redirect(skb, dst->dst_num, 0/*egress*/);
    }
  }
  return 0;
}

