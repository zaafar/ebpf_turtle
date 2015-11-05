// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>
#define TOTAL_PORTS 6 //[BRIDGE] Total ports = number of hosts attached + 1
#define TOTAL_HOSTS 8
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

struct mac_key {
  u64 mac;
};

struct host_info {
  u32 ifindex;
  u64 rx_pkts;
  u64 tx_pkts;
};

struct config {
  u32 ifindex;
};


struct router_ifc {
  u32 ip_addr;
  u64 mac_address;
  u32 subnet;
  u64 rx_pkts;
  u64 tx_pkts;
};

struct router_host_info {
  u32 ifindex;
  u64 mac;
};

//BPF TABLES TO CONTAIN ALL PROGRAMS INFO
BPF_TABLE("prog", u32, u32, vnf_prog, TOTAL_VNFS);

//PEM BPF TABLES
BPF_TABLE("hash", u32, u32, pvm_ifc2vi, TOTAL_HOSTS);
//BPF_TABLE("hash", u32, u32, pem_vi2ifc, TOTAL_HOSTS)

//PATCH PANNEL TABLES
// [TODO zaafar]: NEED to decide total number of entries.
BPF_TABLE("hash", u32, struct ifc_info, forwarder_vi, 1024);


//BR1 TABLES
BPF_TABLE("hash", struct mac_key, struct host_info, mac2host_br1, 10240);
BPF_TABLE("hash", int, struct config, conf_br1, TOTAL_PORTS);

//BR2 TABLES
BPF_TABLE("hash", struct mac_key, struct host_info, mac2host_br2, 10240);
BPF_TABLE("hash", int, struct config, conf_br2, TOTAL_PORTS);


//ROUTER TABLES
BPF_TABLE("hash", u32, struct router_ifc, router_host, 10240);
//BPF_TABLE("hash", u32, struct router_ifc, routes, 10240);
BPF_TABLE("hash", u32, struct router_host_info, r_arp_table, 1024);

// Handle packets from (namespace outside) interface
int pvm_function_p2v(struct __sk_buff *skb) {
  u32 ifindex = skb->ifindex, *vi_num;

  // change from physical interface to virtual interface
  // add it in the packet skb buffer.
  vi_num = pvm_ifc2vi.lookup( &ifindex );
  if (vi_num)
    skb->cb[CB_VI] = *vi_num;

  // pass the packet to patch pannel for further processing.
  vnf_prog.call(skb, PATCH_PANEL);
  return 0;
}

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

int broadcaster(struct __sk_buff *skb) {
  u8 *cursor = 0;
  vnf_prog.call(skb, PATCH_PANEL);
  return 0;
}

int br1_function(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct mac_key src_key = {};
  struct host_info src_info = {};
  //Extract ethernet header from the memory and point cursor to payload of ethernet header.
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  src_key.mac = ethernet->src;
  // bridge virtual interface from where packet arrives.
  src_info.ifindex = skb->cb[CB_VI];
  src_info.rx_pkts = 0;
  src_info.tx_pkts = 0;
  struct host_info *src_host = mac2host_br1.lookup_or_init(&src_key, &src_info);
  lock_xadd(&src_host->rx_pkts, 1);

  struct mac_key dst_key = {ethernet->dst};
  struct host_info *dst_host = mac2host_br1.lookup(&dst_key);

  int cfg_index = 0;
  struct config *cfg = conf_br1.lookup(&cfg_index);
  int broadcaster = 0;
  if (cfg) broadcaster = cfg->ifindex;
  u32 temp_ifindex = 0;
  if (dst_host) {
    skb->cb[CB_VI] = dst_host->ifindex;
    vnf_prog.call(skb, PATCH_PANEL);
    lock_xadd(&dst_host->tx_pkts, 1);
  } else {
    if (ethernet->type == 0x0806) {
      struct arp_t *arp = cursor_advance(cursor, sizeof(*arp));
      //make this logic generic [todo:zaafar]
      u32 temp_ifc = 5000;
      struct router_ifc *rt_info = router_host.lookup( &temp_ifc);
      if (rt_info && arp->tpa == rt_info->ip_addr)
      {
        cfg_index = 1;
        cfg = conf_br1.lookup(&cfg_index);
        if (cfg && skb->cb[CB_VI] != cfg->ifindex) {
          skb->cb[CB_VI] = cfg->ifindex;
          bpf_clone_redirect(skb, broadcaster, 1);
        }
      } else {
        for ( int j=2;j<TOTAL_PORTS;j++ )
        {
          cfg_index = j;
          cfg = conf_br1.lookup(&cfg_index);
          if (cfg && skb->cb[CB_VI] != cfg->ifindex) {
            temp_ifindex = skb->cb[CB_VI];
            skb->cb[CB_VI] = cfg->ifindex;
            bpf_clone_redirect(skb, broadcaster, 1);
            skb->cb[CB_VI] = temp_ifindex;
          }
        }
      }
    }
  }
  return 0;
}

int router_function(struct __sk_buff *skb) {
  u8 *cursor = 0;
  u32 ifindex = skb->cb[CB_VI];
  struct router_ifc *my_info = router_host.lookup( &ifindex);
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  switch (ethernet->type) {
    case 0x0800: goto ip;
    case 0x0806: goto arp;
  }

arp: ;
  struct arp_t *arp = cursor_advance(cursor, sizeof(*arp));
  u32 dst_ip = arp->tpa;
  u32 src_ip = arp->spa;
  u64 src_mac = ethernet->src;
  struct router_host_info host = {};
  host.ifindex = ifindex;
  host.mac = ethernet->src;
  r_arp_table.lookup_or_init(&src_ip, &host);
  if ( my_info && arp->oper == 1 && dst_ip == my_info->ip_addr)
  {
    ethernet->src = my_info->mac_address;
    ethernet->dst = src_mac;

    arp->tha = src_mac;
    arp->tpa = src_ip;
    arp->spa = dst_ip;
    arp->sha = my_info->mac_address;
    arp->oper = 2;

    // no need to change the vi as we are sending the packet back
    vnf_prog.call(skb, PATCH_PANEL);
  }
ip: ;
  // [zaafar todo:] implement routing table logic.
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  u32 pkt_dst = ip->dst;
  struct router_host_info *host_dst = r_arp_table.lookup(&pkt_dst);
  if (host_dst && my_info)
  {
    ethernet->src = my_info->mac_address;
    ethernet->dst = host_dst->mac;
    skb->cb[CB_VI] = host_dst->ifindex;
    vnf_prog.call(skb,PATCH_PANEL);
  }
end: ;
  return 0;
}

int br2_function(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct mac_key src_key = {};
  struct host_info src_info = {};
  //Extract ethernet header from the memory and point cursor to payload of ethernet header.
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  src_key.mac = ethernet->src;
  // bridge virtual interface from where packet arrives.
  src_info.ifindex = skb->cb[CB_VI];
  src_info.rx_pkts = 0;
  src_info.tx_pkts = 0;
  struct host_info *src_host = mac2host_br2.lookup_or_init(&src_key, &src_info);
  lock_xadd(&src_host->rx_pkts, 1);

  struct mac_key dst_key = {ethernet->dst};
  struct host_info *dst_host = mac2host_br2.lookup(&dst_key);

  int cfg_index = 0;
  struct config *cfg = conf_br2.lookup(&cfg_index);
  int broadcaster = 0;
  if (cfg) broadcaster = cfg->ifindex;
  u32 temp_ifindex = 0;
  if (dst_host) {
    skb->cb[CB_VI] = dst_host->ifindex;
    vnf_prog.call(skb, PATCH_PANEL);
    lock_xadd(&dst_host->tx_pkts, 1);
  } else {
    if (ethernet->type == 0x0806) {
      struct arp_t *arp = cursor_advance(cursor, sizeof(*arp));
      u32 temp_ifc = 5001;
      struct router_ifc *rt_info = router_host.lookup( &temp_ifc);
      if (rt_info && arp->tpa == rt_info->ip_addr)
      {
        cfg_index = 1;
        cfg = conf_br2.lookup(&cfg_index);
        if (cfg && skb->cb[CB_VI] != cfg->ifindex) {
          skb->cb[CB_VI] = cfg->ifindex;
          bpf_clone_redirect(skb, broadcaster, 1);
        }
      } else {
        for ( int j=2;j<TOTAL_PORTS;j++ )
        {
          cfg_index = j;
          cfg = conf_br2.lookup(&cfg_index);
          if (cfg && skb->cb[CB_VI] != cfg->ifindex) {
            temp_ifindex = skb->cb[CB_VI];
            skb->cb[CB_VI] = cfg->ifindex;
            bpf_clone_redirect(skb, broadcaster, 1);
            skb->cb[CB_VI] = temp_ifindex;
          }
        }
      }
    }
  }
  return 0;
}
