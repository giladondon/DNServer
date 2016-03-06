"""
Very well done. Please see comments below. Your grade is 100.
"""

import socket
import sys
from random import randint

i, e, o = sys.stdin, sys.stderr, sys.stdout
from scapy.all import *

sys.stdin, sys.stderr, sys.stdout = i, e, o

__author__ = 'Gilad Barak'
__name__ = 'main'

"""
A solution for advanced Scapy exercise from Gvahim Book p.143-144
"""

IP_CURRENT = '172.16.1.3'
DEFAULT_GATEWAY = '172.16.0.11'
DNS_PORT = 53
A_METHOD = 1
IN_CLASS = 1
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
RANDOM_LENGTH = 3
PCKT_GATEWAY_INDEX = 0
PCKT_IP_ID_INDEX = 1
PCKT_DNS_ID_INDEX = 2
COMPLEX_GATEWAY_INDEX_CONDITION = 3
DNS_DATABASE_FORMAT = "[{}] [{}] [{}] {} {}\n"


def is_dns_port(sniffed_packet):
#YANAI: Method documentation?
    return sniffed_packet[UDP].dport == DNS_PORT


def is_dns_packet(sniffed_packet):
#YANAI: Method documentation?
    return DNS in sniffed_packet and DNSQR in sniffed_packet


def is_accepted_method(sniffed_packet):
#YANAI: Method documentation?
    return sniffed_packet[DNSQR].qtype in ACCEPTED_METHODS


def is_query_dns(sniffed_packet):
#YANAI: Method documentation?
    return sniffed_packet[DNS].qr == QUERY_QR


def is_dst_here(sniffed_packet):
#YANAI: Method documentation?
    return sniffed_packet[IP].dst == IP_CURRENT


def is_from_gateway(sniffed_packet):
#YANAI: Method documentation?
    return sniffed_packet[IP].src == DEFAULT_GATEWAY

#YANAI: Constants should be in start of code.
CONDITIONS = [is_dns_packet, is_query_dns, is_dns_port, is_accepted_method, is_dst_here]
GATEWAY_CONDITIONS = [is_dns_packet, is_dns_port, is_dst_here, is_from_gateway]


def filter_packets(sniffed_packet):
#YANAI: Method documentation?
    for condition in CONDITIONS:
        return condition(sniffed_packet)


def filter_gateway_packets(sniffed_packet):
#YANAI: Method documentation?
    for condition in CONDITIONS:
        return condition(sniffed_packet)


def parse_dns_database(line):
    """
    :param line: line from DNS database file
    :return: parsed line into list by [domain, ttl, method, type, rdata]
    Works with formatted database: [domain] [ttl] [method] type rdata
    """
    sections = line.split()
    for section in range(len(sections)):
        sections[section] = sections[section].replace('[', '')
        sections[section] = sections[section].replace(']', '')
    sections[TTL_CELL_INDEX] = int(sections[TTL_CELL_INDEX])
    return sections


def get_database_parsed(database_file):
    """
    :param database_file: database file content by format : [domain] [ttl] [method] type rdata
    :return: list of lists - database of dns records file
    """
    database = []
    for line in database_file.readlines():
        database.append(parse_dns_database(line))
    database_file.close()
    return database

#YANAI: This function is kind of needless, you can just open the file yourself.
def read_file(file_path):
    """
    :param file_path: path to file to be read
    :return: file read binary
    """
    f = open(file_path, 'rb')
    return f


def check_packet_record(pckt, data):
    """
    :param pckt: sniffed dns query packet
    :param data: data line from database dns records
    :return: boolean value if packet matches line
    """
    return (data[DOMAIN_CELL_INDEX] == pckt[DNSQR].qname) and (pckt[DNSQR].qclass is IN_CLASS)


def is_recorded_packet(pckt, database):
    """
    :param pckt: sniffed dns query packet
    :param database: list of lists - database of dns records file
    :return: boolean value if packet in record or not. if True tuple of boolean and index of record
    """
    for data in range(len(database)):
        if check_packet_record(pckt, database[data]):
            return True, data
    return False, -1


def generate_dnsqr(data):
    """
    :param data: line from database records
    :return: DNSQR part of dns layer (qd)
    """
    #YANAI: You keep using the pattern where you put the return variable in a parameter, and then return it. 
    #You can just use: "return DNSQR(qname=data[DOMAIN_CELL_INDEX], qtype=data[TYPE_CELL_INDEX])"
    dnsqr_layer = DNSQR(qname=data[DOMAIN_CELL_INDEX], qtype=data[TYPE_CELL_INDEX])
    return dnsqr_layer


def generate_dnsrr(data):
    """
    :param data: line from database records
    :return: DNSRR part of dns layer (an/ns)
    """
    dnsrr_layer = DNSRR(rrname=data[DOMAIN_CELL_INDEX], type=data[TYPE_CELL_INDEX],  rdata=data[RDATA_CELL_INDEX],
                        ttl=data[TTL_CELL_INDEX])
    return dnsrr_layer


def generate_udp(pckt):
    """
    :param pckt: sniffed dns query packet
    :return: udp layer
    """
    try:
        udp_layer = UDP(sport=DNS_PORT, dport=pckt[UDP].sport)
        return udp_layer
    except IndexError:
        try:
            udp_layer = UDP(sport=DNS_PORT, dport=pckt[UDP in ICMP].sport)
            return udp_layer
        except TypeError:
            pass


def generate_ip(pckt):
    """
    :param pckt: sniffed dns query packet
    :return: ip layer
    """
    ip_layer = IP(id=pckt[IP].id, src=IP_CURRENT, dst=pckt[IP].src)
    return ip_layer


def generate_dns(pckt, data):
    """
    :param pckt: sniffed dns query packet
    :param data: line from database records
    :return: dns layer including dnsrr and dnsqr
    """
    dns_layer = DNS(qd=pckt[DNSQR], an=generate_dnsrr(data), id=pckt[DNS].id)
    return dns_layer


def send_recorded_answer_packet(pckt, data):
    """
    :param pckt: sniffed dns query packet
    :param data: line from database records
    Sends answer packet
    """
    answer = generate_ip(pckt) / generate_udp(pckt) / generate_dns(pckt, data)
    send(answer)


def send_not_recorded_answer_packet(pckt):
    """
    :param pckt: sniffed dns query packet
    :return : Boolean value if process successful or not
    Sends no-such-name packet
    """
    answer = generate_ip(pckt) / generate_udp(pckt) / DNS(rcode=NO_SUCH_NAME, id=pckt[DNS].id, qd=pckt[DNS].qd,
                                                          qdcount=pckt[DNS].qdcount)
    try:
        send(answer)
        return True
    except (Scapy_Exception, OSError):
        return False


def refactor_packet_gateway(pckt):
    """
    :param pckt: sniffed dns query packet
    :return : refactored packet
    """
    ip_layer = IP(src=IP_CURRENT, dst=DEFAULT_GATEWAY)
    udp_layer = UDP(sport=DNS_PORT, dport=DNS_PORT)
    dnsqr_layer = DNSQR(qname=pckt[DNS].qd.qname, qtype=pckt[DNS].qd.qtype, qclass=pckt[DNS].qd.qclass)
    return ip_layer / udp_layer / DNS(qd=dnsqr_layer)


def update_database(authorised_answer):
    """
    :param pckt: sniffed dns query packet
    :return : true of process successful
    """
    database_file = open(DATABASE_TXT_PATH + os.sep + DATABASE_TXT_NAME, 'a')
    database_file_read = open(DATABASE_TXT_PATH + os.sep + DATABASE_TXT_NAME, 'rb')
    data_line = DNS_DATABASE_FORMAT.format(authorised_answer.rrname, authorised_answer.ttl,
                                                   authorised_answer.rclass, authorised_answer.type,
                                                   authorised_answer.rdata)
    if not data_line in database_file_read.readlines():
        database_file.write(data_line)
    database_file.close()
    return True


def bounce_to_gateway(pckt):
    """
    :param pckt: sniffed dns query packet
    :return : Boolean value if process successful or not
    bounces unknown query to gateway and looks for answer.
    """
    #YANAI: These three lines could be a function called "query_gateway".
    pckt_ans = refactor_packet_gateway(pckt)
    gateway_answer = sr1(pckt_ans)
    answers_filtered = filter_answers(gateway_answer, pckt)
    if answers_filtered[0]:
        rr_answer = answers_filtered[1]
        answer = generate_ip(pckt) / generate_udp(pckt) / DNS(qd=pckt[DNSQR], id=pckt[DNS].id, an=rr_answer)
        if answer[DNS].an is None:
            send_not_recorded_answer_packet(pckt)
            return True
        for answer_data_index in range(answer[DNS].ancount):
            update_database(answer[DNS].an[answer_data_index])
        try:
            send(answer)
            return True
        except (Scapy_Exception, OSError):
            return False
        finally:
            return False


def filter_answers(answer_packet, pckt):
    """
    :param answer_packet: packet received from default gateway - answering dns query
    :param pckt: sniffed dns query packet
    :return : (Boolean value if process successful or not, filtered answers)
    """
    if answer_packet[DNS].an is None and answer_packet[DNS].ns is not None:
        return True, filter_ns_answers(answer_packet, pckt)

    elif answer_packet[DNS].ns is None and answer_packet[DNS].an is not None:
        return True, filter_an_answers(answer_packet, pckt)
    try:
        if answer_packet[DNS].ar is not None:
            return True, filter_ar_answers(answer_packet, pckt)
    except TypeError:
        pass
    finally:
        return False, 0


def filter_ns_answers(answer_packet, pckt):
    """
    :param answer_packet: packet received from default gateway - answering dns query
    :param pckt: sniffed dns query packet
    :return : response part for answer packet
    """
    for response_rr in range(answer_packet[DNS].nscount):
            if answer_packet[DNS].ns[response_rr].type is pckt[DNS].qd.qtype \
                    and answer_packet[DNS].ns[response_rr].rclass is pckt[DNS].qd.qclass:
                return answer_packet[DNS].ns[response_rr]


def filter_an_answers(answer_packet, pckt):
    """
    :param answer_packet: packet received from default gateway - answering dns query
    :param pckt: sniffed dns query packet
    :return :response part for answer packet
    """
    for response_rr in range(answer_packet[DNS].nscount):
            if answer_packet[DNS].ns[response_rr].type is pckt[DNS].qd.qtype \
                    and answer_packet[DNS].ns[response_rr].rclass is pckt[DNS].qd.qclass:
                return answer_packet[DNS].ns[response_rr]


def filter_ar_answers(answer_packet, pckt):
    """
    :param answer_packet: packet received from default gateway - answering dns query
    :param pckt: sniffed dns query packet
    :return : response part for answer packet
    """
    for response_rr in range(answer_packet[DNS].arcount):
                if answer_packet[DNS].ns[response_rr].type is pckt[DNS].qd.qtype \
                        and answer_packet[DNS].ns[response_rr].rclass is pckt[DNS].qd.qclass:
                    return answer_packet[DNS].ns[response_rr]


def main():
    while True:
        dns_records_database = get_database_parsed(read_file(DATABASE_TXT_PATH + os.sep + DATABASE_TXT_NAME))
        current_packet = sniff(count=1, lfilter=filter_packets)[0]
        temp_value = is_recorded_packet(current_packet, dns_records_database)
        if temp_value[0]:
            index_record = temp_value[1]
            try:
                send_recorded_answer_packet(current_packet, dns_records_database[index_record])
            except (Scapy_Exception, OSError):
                pass
        elif not bounce_to_gateway(current_packet):
            try:
                send_not_recorded_answer_packet(current_packet)
            except (Scapy_Exception, OSError):
                pass


if __name__ == "main":
    main()
