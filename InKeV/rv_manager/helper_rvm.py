from bcc import BPF
from pyroute2 import IPRoute
from ctypes import c_int, c_uint


class rv_manager(object):

    def __init__(self):
        self.ipr = IPRoute()
        self.dataplane = BPF(src_file="rv_manager/rv_manager.c")
        # Loading Tables from dp
        self.next = self.dataplane.get_table("next_hop")
        self.ifc2vi = self.dataplane.get_table("rvm_ifc2vi")
        self.vi2ifc = self.dataplane.get_table("rvm_vi2ifc")
        # Loading Functions from db
        self.func_phy2virt = self.dataplane.load_func(
            "rvm_function_p2v", BPF.SCHED_CLS)
        self.func_virt2phy = self.dataplane.load_func(
            "rvm_function_v2p", BPF.SCHED_CLS)

    def set_next_hop(self, next_vnf):
        self.next[self.next.Key(0)] = self.next.Leaf(next_vnf)

    def get_fd(self):
        return self.func_virt2phy.fd

    def set_bpf_egress(self, ifc_index, func):
        self.ipr.tc("add", "ingress", ifc_index, "ffff:")
        self.ipr.tc("add-filter", "bpf", ifc_index, ":1", fd=func.fd,
                    name=func.name, parent="ffff:", action="drop", classid=1)

    def add_new_vm(self, phy_iface_index, virt_iface_index):
        self.ifc2vi[self.ifc2vi.Key(phy_iface_index)] = self.ifc2vi.Leaf(
            virt_iface_index)
        self.vi2ifc[self.vi2ifc.Key(virt_iface_index)] = self.vi2ifc.Leaf(
            phy_iface_index)

        self.set_bpf_egress(phy_iface_index, self.func_phy2virt)


# UNIT TESTING
# vm = rv_manager()
# vm.set_next_hop(vm.get_rvm_fd())
# vm.add_new_vm(1, 1000)
