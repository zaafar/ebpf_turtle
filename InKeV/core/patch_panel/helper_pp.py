from bcc import BPF


class patch_panel(object):

    def __init__(self):
        self.vnf_counter = 0
        self.dataplane = BPF(src_file="core/patch_panel/patch_panel.c")
        # Loading Tables from db
        self.vnf_map = self.dataplane.get_table("vnf_prog")
        self.forwarder = self.dataplane.get_table("forwarder_vi")
        # Loading functions from db
        self.func_linker = self.dataplane.load_func("linker", BPF.SCHED_CLS)

    def get_fd(self):
        return self.func_linker.fd

    # TODO: delete vnf code.
    def add_new_vnf(self, vnf_function_fd):
        # TODO: add code to check if vnf_fd already exists.
        self.vnf_map[self.vnf_map.Key(
            self.vnf_counter)] = self.vnf_map.Leaf(vnf_function_fd)
        self.vnf_counter = self.vnf_counter + 1
        return self.vnf_counter - 1

    def link_interfaces(self, vnf_from_iface, is_virtual, vnf_to_iface, vnf_to_fd):
        self.forwarder[self.forwarder.Key(
            vnf_from_iface)] = self.forwarder.Leaf(
            is_virtual, vnf_to_iface, vnf_to_fd)


# Unit Testing
# pp = patch_panel()
# print pp.add_new_vnf(pp.get_fd())
# pp.link_interfaces(100, 1, 200, 0)
