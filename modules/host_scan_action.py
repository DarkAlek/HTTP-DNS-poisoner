import nmap


class HostScanActionModule:
    '''Manages host scanning'''
    def __init__(self):
        self.nm = nmap.PortScanner()

    def run(self):
        print(self.get_available_hosts())

    def get_available_hosts(self):
        self.nm.scan(
            hosts='192.168.1.1/24', arguments='-n -sP -PE -PA21,22,23,80,3389')
        return self.nm.all_hosts()

    def print_host_os(self, host_ip):
        self.nm.scan(hosts=host_ip, arguments='-O')

        if 'osclass' in self.nm[host_ip]:
            for osclass in self.nm[host_ip]['osclass']:
                print('OsClass.type : {0}'.format(osclass['type']))
                print('OsClass.vendor : {0}'.format(osclass['vendor']))
                print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
                print('OsClass.osgen : {0}'.format(osclass['osgen']))
                print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
                print('')

        if 'osmatch' in self.nm[host_ip]:
            for osmatch in self.nm[host_ip]['osmatch']:
                print('OsMatch.name : {0}'.format(osmatch['name']))
                print('OsMatch.accuracy : {0}'.format(osmatch['accuracy']))
                print('OsMatch.line : {0}'.format(osmatch['line']))
                print('')

        if 'fingerprint' in self.nm[host_ip]:
            print('Fingerprint : {0}'.format(self.nm[host_ip]['fingerprint']))

        if 'mac' in self.nm[host_ip]['addresses']:
            print(self.nm[host_ip]['addresses'], self.nm[host_ip]['vendor'])

    def set_options(self):
        pass

    def print_basic_info(self):
        pass

    def print_extended_info(self):
        pass
