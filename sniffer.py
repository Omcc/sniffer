import socket
import struct

NL1 = '\n'
NL2 = '\n\n'
NL3 = '\n\n\n'
TAB1 = '\t'
TAB2 = '\t\t'
TAB3 = '\t\t\t'
ETH_TYPE = {
    '0x0800':'IPv4',
    '0x0806': 'ARP',
    '0x0842': 'Wake-on-LAN',
    '0x22F0': 'Audio Video Transport Protocol',
    '0x22F3': 'IETF TRILL Protocol',
    '0x22EA': 'Stream Reservation Protocol',
    '0x6002': 'DEC MOP RC',
    '0x6003': 'DECnet Phase IV, DNA Routing',
    '0x6004': 'DEC LAT',
    '0x8035': 'Reverse Address Resolution Protocol ',
    '0x809B': 'AppleTalk',
    '0x80F3': 'AppleTalk Address Resolution Protocol (AARP)'

}

def sniff():
    conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))


    while True:
        raw_data,addr= conn.recvfrom(128128)
        dest_mac_addr,source_mac_addr,ether_type,packet = ethernet_frame(raw_data)

        ip_version,ttl,protocol,source_ip,dest_ip,segment = ipv4_network_packet(packet)
        if(protocol==17):
            source_port,dest_port,data = udp_segment(segment);
            print(data)
        else:

            source_port, dest_port, seq_number, ack_number, urg, ack, psh, rst, syn, fin, data = tcp_segment(segment)
            print(data)












def ethernet_frame(frame):
    dest_mac_addr,source_mac_addr, ether_type = struct.unpack("! 6s 6s 2s",frame[:14])

    dest_mac_addr = format_mac(dest_mac_addr)
    source_mac_addr=format_mac(source_mac_addr)

    ether_type = format_hex(ether_type)
    if(ether_type in ETH_TYPE.keys()):
        ether_type = ETH_TYPE[ether_type]
    print("-------------------------------------------------")
    print(NL2+ "Ethernet Frame(Layer 2):")
    print(TAB1 + "Destination Mac: {}".format(dest_mac_addr) +NL1+TAB1 + "Source Mac: {}".format(source_mac_addr))
    print(TAB1 + "EtherType: {}".format(ether_type))


    return dest_mac_addr,source_mac_addr,ether_type,frame[14:]

def ipv4_network_packet(packet):
    version_ihl = packet[0]

    version = version_ihl >> 4
    ihl = (version_ihl & 15) * 4
    ttl,protocol,source_ip,dest_ip = struct.unpack("! 8x B B 2x 4s 4s",packet[:20])


    source_ip = format_ip(source_ip)
    dest_ip = format_ip(dest_ip)


    print(NL2 + "Network Packet (Layer 3):")
    print(TAB1 + "Destination Ip : {}".format(dest_ip) + NL1 + TAB1 + "Source Ip: {}".format(source_ip))
    print(TAB1 + "Ip Version: {} TTL: {} protocol: {} ".format(version,ttl,protocol))

    return version,ttl,protocol,source_ip,dest_ip,packet[ihl:]


def tcp_segment(segment):
    source_port,dest_port,seq_number,ack_number,header_length_flags= struct.unpack("! H H I I H",segment[0:14])

    header_length = (header_length_flags >> 12) * 4
    urg = (header_length_flags >> 5) & 1
    ack = (header_length_flags >> 4) & 1
    psh = (header_length_flags >> 3) & 1
    rst = (header_length_flags >> 2) & 1
    syn = (header_length_flags >> 1) & 1
    fin = (header_length_flags) & 1

    data = segment[header_length:]

    print(NL2 + "TCP Segment(Layer 4):")
    print(TAB1 + "Destination Port : {}".format(dest_port) + NL1 + TAB1 + "Source Port: {}".format(source_port))
    print(TAB1 + "Acknowledgement Number: {} Sequence Number: {}".format(ack_number,seq_number))
    print(TAB1 + "Flags :::: urg: {} ack: {} psh: {} rst: {} syn: {} fin: {}".format(urg,ack,psh,rst,syn,fin))

    return source_port,dest_port,seq_number,ack_number,urg,ack,psh,rst,syn,fin,data


def udp_segment(segment):
    source_port,dest_port,length= struct.unpack("! H H H",segment[0:6])


    print(NL2 + "UDP Segment(Layer 4):")
    print(TAB1 + "Destination Port : {}".format(dest_port) + NL1 + TAB1 + "Source Port: {}".format(source_port))

    data = segment[8:]
    return source_port,dest_port,data




def format_mac(mac):
    formatted_mac=map("{:02x}".format,mac)

    return ":".join(formatted_mac).upper()



## Utility functions
def format_hex(data):
    formatted_hex = map("{:02x}".format,data)
    return "0x" + "".join(formatted_hex).upper()

def format_ip(ip):
    formatted_ip = map(str,ip)
    return ".".join(formatted_ip)







sniff()
