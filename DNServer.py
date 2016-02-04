import sys
i, e, o = sys.stdin, sys.stderr, sys.stdout
from scapy.all import *
sys.stdin, sys.stderr, sys.stdout = i, e, o

__author__ = 'Gilad Barak'
__name__ = 'main'

"""
A solution for advanced Scapy exercise from Gvahim Book p.143-144
"""

IP = '127.0.0.1'
DNS_PORT = 53
A_METHOD = 1
PTR_METHOD = 12
QUERY_QR = 0
ACCEPTED_METHODS = {A_METHOD, PTR_METHOD}


def is_dns_port(sniffed_packet):
    if sniffed_packet[UDP].dport == DNS_PORT:
        return True
    else:
        return False


def is_dns_packet(sniffed_packet):
    if DNS in sniffed_packet and DNSQR in sniffed_packet:
        return True
    else:
        return False


def is_accepted_method(sniffed_packet):
    if sniffed_packet[DNSQR].qtype in ACCEPTED_METHODS:
        return True
    else:
        return False


def is_query_dns(sniffed_packet):
    if sniffed_packet[DNS].qr == QUERY_QR:
        return True
    else:
        return False

CONDITIONS = [is_dns_packet, is_query_dns, is_dns_port, is_accepted_method]


def filter_packets(sniffed_packet):
    for condition in CONDITIONS:
        if not condition(sniffed_packet):
            return False
    return True


def main():
    while True:
        current_packet = sniff(count=1, lfilter=filter_packets)


if __name__ == "main":
    main()