import socket
import struct



def sniff():
    conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))


    while True:
        raw_data,addr= conn.recvfrom(128128)
        dest_mac_addr,source_mac_addr,ether_type,packet = ethernet_frame(raw_data)

        ip_version,ttl,protocol,source_ip,dest_ip,segment = ipv4_network_packet(packet)
        tcp_segment(segment)



def ethernet_frame(frame):
    dest_mac_addr,source_mac_addr, ether_type = struct.unpack("! 6s 6s 2s",frame[:14])

    dest_mac_addr = format_mac(dest_mac_addr)
    source_mac_addr=format_mac(source_mac_addr)

    ether_type = format_hex(ether_type)


    return dest_mac_addr,source_mac_addr,ether_type,frame[14:]

def ipv4_network_packet(packet):
    version_ihl = packet[0]

    version = version_ihl >> 4
    ihl = (version_ihl & 15) * 4
    ttl,protocol,source_ip,dest_ip = struct.unpack("! 8x B B 2x 4s 4s",packet[:20])


    source_ip = format_ip(source_ip)
    dest_ip = format_ip(dest_ip)

    return version,ttl,protocol,source_ip,dest_ip,packet[ihl:]







def format_mac(mac):
    formatted_mac=map("{:02x}".format,mac)

    return ":".join(formatted_mac).upper()


def format_hex(data):
    formatted_hex = map("{:02x}".format,data)
    return "0x" + "".join(formatted_hex).upper()

def format_ip(ip):
    formatted_ip = map(str,ip)
    return ".".join(formatted_ip)

def tcp_segment(segment):
    source_port,dest_port = struct.unpack("! H H",segment[0:4])


sniff()
