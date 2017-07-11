from modules.http_modify_action import HttpModifyActionModule
from modules.host_scan_action import HostScanActionModule


class BaseActionModule:
    '''Base class for actions (do real job) modules'''
    def __init__(self):
        pass

    def print_basic_info(self):
        pass

    def print_extended_info(self):
        pass

    def run(self):
        pass

    def set_options(self):
        pass


class AppController:
    '''Controlls flow of application'''
    target = None

    def __init__(self):
        pass

    def set_target(self, host_ip):
        self.target = host_ip

    def load_module(self, action_module):
        self.action_module = action_module()

    def make_action(self):
        self.action_module.run()

    def set_options(self):
        self.action_module.set_options()


# Below example of using default module
'''
app = AppController()
app.load_module(HostScanActionModule)
app.set_options()
app.make_action()
'''

app = AppController()
app.load_module(HttpModifyActionModule)
app.set_options()
app.make_action()

# host_scanner = HostScanManager()
# active_hosts = host_scanner.get_available_hosts()

# print('Available hosts:')
# for i in range(0, len(active_hosts)):
#     ip_host = active_hosts[i]
#     print("%d. %s" % (i+1, ip_host))


# host_info = host_scanner.get_host_os('192.168.1.228')
