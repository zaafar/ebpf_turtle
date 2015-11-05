
//ROUTER TABLES
BPF_TABLE("hash", u32, struct router_ifc, router_host, 10240);
//BPF_TABLE("hash", u32, struct router_ifc, routes, 10240);
BPF_TABLE("hash", u32, struct router_host_info, r_arp_table, 1024);

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

