import socket
import sys
i, e, o = sys.stdin, sys.stderr, sys.stdout
from scapy.all import *
sys.stdin, sys.stderr, sys.stdout = i, e, o

__author__ = 'Gilad Barak'
__name__ = 'main'

"""
A solution for advanced Scapy exercise from Gvahim Book p.143-144
"""

IP_CURRENT = '172.16.1.93'
DNS_PORT = 53
A_METHOD = 1
PTR_METHOD = 12
QUERY_QR = 0
ACCEPTED_METHODS = {A_METHOD, PTR_METHOD}
DATABASE_TXT_PATH = "L:\CyberEldad\gilad\DNServer"
DATABASE_TXT_NAME = "Records.txt"
DOMAIN_CELL_INDEX = 0
TTL_CELL_INDEX = 1
METHOD_CELL_INDEX = 2
TYPE_CELL_INDEX = 3
RDATA_CELL_INDEX = 4
NO_SUCH_NAME = 3
IN = '1'


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
    for i in range(len(sections)):
        sections[i] = sections[i].replace('[', '')
        sections[i] = sections[i].replace(']', '')
    sections[TTL_CELL_INDEX] = int(sections[TTL_CELL_INDEX])
    return sections


def get_database_parsed(database_file):
    """
    : param : database file content by format : [domain] [ttl] [method] type rdata
    : return : list of lists - database of dns records file
    """
    database = []
    for line in database_file.readlines():
        database.append(parse_dns_database(line))
    return database


def read_file(file_path):
    """
    : param : path to file to be read
    : return : file read binary
    """
    f = open(file_path, 'rb')
    return f


def check_packet_record(pckt, data):
    """
    : param : sniffed dns query packet
    : param : data - line from database dns records
    : return : boolean value if packet matches line
    """
    print(data[DOMAIN_CELL_INDEX] + ' - ' + pckt[DNSQR].qname)
    print(data[DOMAIN_CELL_INDEX] == pckt[DNSQR].qname)
    print(str(pckt[DNSQR].qclass) is '1')
    return data[DOMAIN_CELL_INDEX] == pckt[DNSQR].qname and pckt[DNSQR].qclass == 1


def is_recorded_packet(pckt, database):
    """
    : param : sniffed dns query packet
    : param : list of lists - database of dns records file
    : return : boolean value if packet in record or not. if True tuple of boolean and index of record
    """
    print database
    for i in range(len(database)):
        if check_packet_record(pckt, database[i]):
            print('AY' + str(i))
            return True, i
    return False, -1


def get_packet_source(pckt):
    """
    : param : sniffed dns query packet
    : return : packet source
    """
    return pckt[IP].src


def get_packet_ip_id(pckt):
    """
    : param : sniffed dns query packet
    : return : packet ip id
    """
    return pckt[IP].id


def get_packet_dns_id(pckt):
    """
    : param : sniffed dns query packet
    : return : packet udp id
    """
    return pckt[DNS].id


def get_packet_sport(pckt):
    """
    : param : sniffed dns query packet
    : return : packet source port
    """
    return pckt[UDP].sport


def generate_dnsqr(data):
    """
    : param : line from database records
    : return : dnsqr part of dns layer
    """
    dnsqr_layer = DNSQR(qname=data[DOMAIN_CELL_INDEX], qtype=data[TYPE_CELL_INDEX])
    return dnsqr_layer


def generate_dnsrr(data):
    """
    : param : line from database records
    : return : dnsqr part of dns layer
    """
    dnsrr_layer = DNSRR(rrname=data[DOMAIN_CELL_INDEX], type=data[TYPE_CELL_INDEX],\
                        ttl=data[TTL_CELL_INDEX], rdata=data[RDATA_CELL_INDEX])
    return dnsrr_layer


def generate_udp(pckt):
    """
    : param : sniffed dns query packet
    : return : udp layer
    """
    udp_layer = UDP(sport=DNS_PORT, dport=get_packet_sport(pckt))
    return udp_layer


def generate_ip(pckt):
    """
    : param : sniffed dns query packet
    : return : ip layer
    """
    ip_layer = IP(id=pckt[IP].id, src=IP_CURRENT, dst=pckt[IP].src)
    return ip_layer


def generate_dns(pckt, data):
    """
    : param : sniffed dns query packet
    : param : line from database records
    : return : dns layer including dnsrr and dnsqr
    """
    dns_layer = DNS(qd=pckt[DNSQR], an=generate_dnsrr(data), id=pckt[DNS].id)
    return dns_layer


def send_recorded_answer_packet(pckt, data):
    """
    : param : sniffed dns query packet
    : param : line from database records
    Sends answer packet
    """
    answer = generate_ip(pckt)/generate_udp(pckt)/generate_dns(pckt, data)
    send(answer)


def send_not_recorded_answer_packet(pckt):
    """
    Sends no-such-name packet
    """
    answer = generate_ip(pckt)/generate_udp(pckt)/DNS(rcode=NO_SUCH_NAME, id=get_packet_dns_id(pckt), qd=pckt[DNS].qd,
                                                       qdcount=pckt[DNS].qdcount)
    send(answer)


def main():
    dns_records_database = DATABASE_TXT_PATH + os.sep + DATABASE_TXT_NAME
    dns_records_database = get_database_parsed(read_file(dns_records_database))
    while True:
        current_packet = sniff(count=1, lfilter=filter_packets)[0]
        if is_recorded_packet(current_packet, dns_records_database)[0]:
            index_record = is_recorded_packet(current_packet, dns_records_database)[1]
            send_recorded_answer_packet(current_packet, dns_records_database[index_record])
        else:
            send_not_recorded_answer_packet(current_packet)


if __name__ == "main":
    main()