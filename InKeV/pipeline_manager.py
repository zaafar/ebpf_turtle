from patch_panel.helper_pp import patch_panel
import importlib


class pipeline_manager(object):

    def constants(self):
        self.RVM = 0
        self.unique_viface_counter = 0

    def __init__(self):
        self.constants()
        self.vnf_list = []
        self.workload_list = []
        # Loading patch panel and rv_manager vnf.
        # They are must have vnf for every topology.
        self.patch_panel = patch_panel()
        self.load_vnf("rv_manager.helper_rvm", "rv_manager")
        self.vnf_list[self.RVM][0].set_next_hop(self.patch_panel.get_fd())

    def generate_unique_viface(self):
        self.unique_viface_counter = self.unique_viface_counter + 1
        return self.unique_viface_counter

    def load_vnf(self, path, vnf_class_name):
        mod = __import__(path)
        components = (path + "." + vnf_class_name).split('.')
        for comp in components[1:]:
            mod = getattr(mod, comp)
        instance = mod()
        self.vnf_list.append(
            [instance, self.patch_panel.add_new_vnf(instance.get_fd())])
        return self.vnf_list[len(self.vnf_list) - 1]

    def delete_vnf(self, vnf_counter):
        pass

    def load_workload(self, workload_phy_port, attached_with_vnf_fd, attached_with_vport):
        unique_virtual_iface = generate_unique_viface()
        self.vnf_list[self.RVM][0].add_new_workload(
            workload_phy_port, unique_virtual_iface)
        self.patch_panel.link_interfaces(
            unique_virtual_iface, attached_with_vport, attached_with_vnf_fd)
        self.patch_panel.link_interfaces(
            attached_with_vport, unique_virtual_iface, self.vnf_list[self.RVM][1])

    def delete_workload(self):
        pass

# Unit Test
# pm = pipeline_manager()
