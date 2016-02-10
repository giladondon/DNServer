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
DATABASE_TXT_PATH = "F:\Cyber\DNServer"
DATABASE_TXT_NAME = "Records.txt"


def is_dns_port(sniffed_packet):
    return sniffed_packet[UDP].dport == DNS_PORT


def is_dns_packet(sniffed_packet):
    return DNS in sniffed_packet and DNSQR in sniffed_packet


def is_accepted_method(sniffed_packet):
    return sniffed_packet[DNSQR].qtype in ACCEPTED_METHODS


def is_query_dns(sniffed_packet):
    return sniffed_packet[DNS].qr == QUERY_QR

CONDITIONS = [is_dns_packet, is_query_dns, is_dns_port, is_accepted_method]


def filter_packets(sniffed_packet):
    for condition in CONDITIONS:
        if not condition(sniffed_packet):
            return False
    return True


def parse_dns_database(line):
    """
    : param : line from DNS database file
    : return : parsed line into list by [domain, ttl, method, type, rdata]
    Works with formatted database: [domain] [ttl] [method] type rdata
    """
    sections = line.split()
    for section in sections:
        sections = section.replace('[', '')
    return sections


def get_database_parsed(database_file):
    """
    : param : database file content by format : [domain] [ttl] [method] type rdata
    """
    database = []
    for line in database_file.readLines():
        database.append(parse_dns_database(line))
    return database


def main():
    while True:
        current_packet = sniff(count=1, lfilter=filter_packets)


if __name__ == "main":
    main()