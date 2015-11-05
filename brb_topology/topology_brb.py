#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from builtins import input
from ctypes import c_uint,c_int, c_ulong
from pyroute2 import IPRoute, IPDB, NSPopen
from simulation import Simulation
from netaddr import IPAddress
import socket, struct
ipr = IPRoute()
ipdb = IPDB(nl=ipr)

num_hosts = 4
null = open("/dev/null", "w")

class TunnelSimulation(Simulation):
    def __init__(self, ipdb):
        super(TunnelSimulation, self).__init__(ipdb)

    def mac2bin(self, mac):
        temp = "\0\0" + mac.replace(':', '').decode('hex')
        addr, = struct.unpack('!Q', temp)
        return addr


    def ip2bin(self, addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    def start(self):
        # Ingress = attached to tc ingress class on bridge
        # Egress = attached to tc engress class on namespace (outside) interface
        # Loading bpf functions/maps.
        brb_code = BPF(src_file="brb_topology_with_patch_pannel.c")
        pvm_fn = brb_code.load_func("pvm_function_p2v", BPF.SCHED_CLS)
        patchpanel_fn  = brb_code.load_func("patch_panel_function", BPF.SCHED_CLS)
        broadcaster_fn = brb_code.load_func("broadcaster", BPF.SCHED_CLS)
        br1_fn = brb_code.load_func("br1_function", BPF.SCHED_CLS)
        print("loading router code")
        rt_fn = brb_code.load_func("router_function", BPF.SCHED_CLS)
        br2_fn = brb_code.load_func("br2_function", BPF.SCHED_CLS)

        vnf_prog   = brb_code.get_table("vnf_prog")
        pvm_ifc2vi = brb_code.get_table("pvm_ifc2vi")
        forward_vi = brb_code.get_table("forwarder_vi")

        mac2host_br1 = brb_code.get_table("mac2host_br1")
        conf_br1 = brb_code.get_table("conf_br1")
        mac2host_br2 = brb_code.get_table("mac2host_br2")
        conf_br2 = brb_code.get_table("conf_br2")
        router_host = brb_code.get_table("router_host")
        #arp_table = brb_code.get_table("arp_table")


        vnf_prog[c_int(0)] = c_int(patchpanel_fn.fd)
        vnf_prog[c_int(1)] = c_int(pvm_fn.fd)
        vnf_prog[c_int(2)] = c_int(br1_fn.fd)
        vnf_prog[c_int(3)] = c_int(rt_fn.fd)
        vnf_prog[c_int(4)] = c_int(br2_fn.fd)
        #Need to add pem into this list.

        # Setup namespace and their interfaces for demostration of br1.
        host_info_br1 = []
        for i in range(0, num_hosts):
            print("Launching host %i of %i in br1" % (i + 1, num_hosts))
            ipaddr = "172.16.1.%d/24" % (100 + i)
            host_info_br1.append(self._create_ns("host%d" % i, ipaddr=ipaddr,
                disable_ipv6=True))

        # Setup namespace and their interfaces for demostration of br2.
        host_info_br2 = []
        for i in range(0, num_hosts):
            print("Launching host %i of %i in br2" % (i + 1, num_hosts))
            ipaddr = "192.168.1.%d/24" % (100 + i)
            host_info_br2.append(self._create_ns("host%d" % (i+4), ipaddr=ipaddr,
                disable_ipv6=True))

        # creating broadcaster, to help broadcast the unknown packets from bridge
        print("creating broadcaster interface")
        broadcaster = ipdb.create(ifname="bc", kind="dummy").up().commit()
        ipr.tc("add", "ingress", broadcaster.index, "ffff:")
        ipr.tc("add-filter", "bpf", broadcaster.index, ":1", fd=broadcaster_fn.fd,
           name=broadcaster_fn.name, parent="ffff:", action="drop", classid=1)
        print("adding it into bridges")
        conf_br1[c_uint(0)] = conf_br1.Leaf(c_uint(broadcaster.index))
        conf_br2[c_uint(0)] = conf_br2.Leaf(c_uint(broadcaster.index))

        print("attaching router between the bridges br1 and br2")
        conf_br1[c_uint(1)] = conf_br1.Leaf(c_uint(2000))
        conf_br2[c_uint(1)] = conf_br2.Leaf(c_uint(4000))

        forward_vi[c_int(2000)] = forward_vi.Leaf(1, c_uint(5000), c_uint(3) , 0)
        forward_vi[c_int(5000)] = forward_vi.Leaf(1, c_uint(2000), c_uint(2) , 0)

        forward_vi[c_int(4000)] = forward_vi.Leaf(1, c_uint(5001), c_uint(3) , 0)
        forward_vi[c_int(5001)] = forward_vi.Leaf(1, c_uint(4000), c_uint(4) , 0)

        #now tell router about it's interfaces
        router_host[c_int(5000)] = router_host.Leaf(self.ip2bin("172.16.1.1"), self.mac2bin("0d:b5:2f:b4:0b:1f"),0,0,0)
        router_host[c_int(5001)] = router_host.Leaf(self.ip2bin("192.168.1.1"), self.mac2bin("64:65:9c:b4:85:2d"),0,0,0)

        print("creating virutal topology for br1")
        # For each namespace that want to connect to the ebpf bridge
        index = 1
        for host in host_info_br1:
            ipr.tc("add", "ingress", host[1].index, "ffff:")
            ipr.tc("add-filter", "bpf", host[1].index, ":1", fd=pvm_fn.fd,
                   name=pvm_fn.name, parent="ffff:", action="drop", classid=1)
            # Passing namespace interface info to dataplane module.
            pvm_ifc2vi[c_uint(host[1].index)] = c_uint(index+1000)
            forward_vi[c_int(index+1000)] = forward_vi.Leaf(1, c_uint(index+2000), c_uint(2) , 0)
            forward_vi[c_int(index+2000)] = forward_vi.Leaf(0, c_uint(host[1].index), 0 , 0)
            conf_br1[c_uint(index+1)]= conf_br1.Leaf(c_uint(index+2000))
            cmd1 = ["route", "add", "default", "gw","172.16.1.1"]
            nsp = NSPopen(host[0].nl.netns, cmd1)
            nsp.wait(); nsp.release()
            cmd1 = ["arping", "-c", "1", "172.16.1.1","-q"]
            nsp = NSPopen(host[0].nl.netns, cmd1)
            nsp.wait(); nsp.release()
            index = index+1

        print("creating virtual topology for br2")
        # For each namespace that want to connect to the ebpf bridge
        index = 1
        for host in host_info_br2:
            ipr.tc("add", "ingress", host[1].index, "ffff:")
            ipr.tc("add-filter", "bpf", host[1].index, ":1", fd=pvm_fn.fd,
                   name=pvm_fn.name, parent="ffff:", action="drop", classid=1)
            # Passing namespace interface info to dataplane module.
            pvm_ifc2vi[c_uint(host[1].index)] = c_uint(index+3000)
            forward_vi[c_int(index+3000)] = forward_vi.Leaf(1, c_uint(index+4000), c_uint(4) , 0)
            forward_vi[c_int(index+4000)] = forward_vi.Leaf(0, c_uint(host[1].index), 0 , 0)
            conf_br2[c_uint(index+1)]= conf_br2.Leaf(c_uint(index+4000))
            index = index+1
            cmd1 = ["route", "add", "default", "gw","192.168.1.1"]
            nsp = NSPopen(host[0].nl.netns, cmd1)
            nsp.wait(); nsp.release()
            cmd1 = ["arping", "-c", "1", "192.168.1.1","-q"]
            nsp = NSPopen(host[0].nl.netns, cmd1)
            nsp.wait(); nsp.release()
            index = index+1


try:
    sim = TunnelSimulation(ipdb)
    sim.start()
    input("Press enter to quit:")
except Exception,e:
    print str(e)
    if "sim" in locals():
        for p in sim.processes: p.kill(); p.wait(); p.release()
finally:
    if "bc" in ipdb.interfaces: ipdb.interfaces["bc"].remove().commit()
    if "sim" in locals(): sim.release()
    ipdb.release()
    null.close()

