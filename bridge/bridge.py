from bcc import BPF
from builtins import input
from ctypes import c_int
from pyroute2 import IPRoute, IPDB
from simulation import Simulation
from netaddr import IPAddress
ipr = IPRoute()
ipdb = IPDB(nl=ipr)

num_hosts = 2
null = open("/dev/null", "w")

class BridgeSimulation(Simulation):
    def __init__(self, ipdb):
        super(BridgeSimulation, self).__init__(ipdb)

    def start(self):
        # Ingress = attached to tc ingress class on bridge
        # Egress = attached to tc engress class on namespace (outside) interface
        # Loading bpf functions/maps.
        bridge_code = BPF(src_file="bridge.c")
        ingress_fn = bridge_code.load_func("handle_ingress", BPF.SCHED_CLS)
        egress_fn  = bridge_code.load_func("handle_egress", BPF.SCHED_CLS)
        mac2host   = bridge_code.get_table("mac2host")
        conf       = bridge_code.get_table("conf")

        # Creating dummy interface behind which ebpf code will do bridging.
        ebpf_bridge = ipdb.create(ifname="ebpf_br", kind="dummy").up().commit()
        ipr.tc("add", "ingress", ebpf_bridge.index, "ffff:")
        ipr.tc("add-filter", "bpf", ebpf_bridge.index, ":1", fd=egress_fn.fd,
           name=egress_fn.name, parent="ffff:", action="drop", classid=1)

        # Passing bridge index number to dataplane module
        conf[c_int(0)] = c_int(ebpf_bridge.index)

        # Setup namespace and their interfaces for demostration.
        host_info = []
        for i in range(0, num_hosts):
            print("Launching host %i of %i" % (i + 1, num_hosts))
            ipaddr = "172.16.1.%d/24" % (100 + i)
            host_info.append(self._create_ns("host%d" % i, ipaddr=ipaddr,
                disable_ipv6=True))

        # For each namespace that want to connect to the ebpf bridge
        # We link it to the dummy interface behind which we run ebpf learning/forwarding code
        # logically: Attaching individual namespace interface into the ebpf bridge.
        # programmatically: running ebpf engress code on each interface
        temp_index=1
        for host in host_info:
            ipr.tc("add", "ingress", host[1].index, "ffff:")
            ipr.tc("add-filter", "bpf", host[1].index, ":1", fd=ingress_fn.fd,
                   name=ingress_fn.name, parent="ffff:", action="drop", classid=1)
            # Passing namespace interface info to dataplane module.
            conf[c_int(temp_index)] = c_int(host[1].index)
            temp_index=temp_index+1

try:
    sim = BridgeSimulation(ipdb)
    sim.start()
    input("Press enter to quit:")
except Exception,e:
    print str(e)
    if "sim" in locals():
        for p in sim.processes: p.kill(); p.wait(); p.release()
finally:
    if "ebpf_br" in ipdb.interfaces: ipdb.interfaces["ebpf_br"].remove().commit()
    if "sim" in locals(): sim.release()
    ipdb.release()
    null.close()


