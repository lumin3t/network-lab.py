import socket 
import textwrap 
import struct

#To add spaces 
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '
TAB_5 = '\t\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '
DATA_TAB_5 = '\t\t\t\t\t '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # Create a raw socket and bind it to the public interface
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet frame: ")
        print(TAB_1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))
        #Eth protocol is 8 when its ipv4 regular internet traffic 
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1+ "IPv4 Packet: ")
            print(TAB_2+"Version: {}, Header Length: {}, TTL {}".format(version, header_length, ttl))
            print(TAB_2+"Protocol: {}, Source: {}, Target {}".format(proto, src, target))
            #ICMP
            if proto == 1:
                icmp_type, code, checksum, data = unpack_icmp(data)
                print(TAB_1+"ICMP Packet: ")
                print(TAB_2+"Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                print(TAB_2+"Data: ")
                print(format_multi_line(DATA_TAB_3, data))
            elif proto == 6: #TCP
                src_port, dest_port, sequence, acknowledgement, urg, ack, psh, rst, syn, fin, data = tcp_segment(data)
                print(TAB_1+"TCP Segment: ")
                print(TAB_2+"Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print(TAB_2+"Sequence: {}, Acknowledgement: {}".format(sequence, acknowledgement))
                print(TAB_2+"Flags: ")
                print(TAB_3+"URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(urg, ack, psh, rst, syn, fin))
                print(TAB_2+"Data: ")
                print(format_multi_line(DATA_TAB_3, data))
            elif proto == 17: #UDP
                src_port, dest_port, size, data = udp_segment(data)
                print(TAB_1+"UDP Segment: ")
                print(TAB_2+"Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, size))
                print(TAB_2+"Data: ")
                print(format_multi_line(DATA_TAB_3, data))
            else: #Other
                print(TAB_1+"Other IPv4 Data: ")
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print("Ethernet Data: ")
            print(format_multi_line(DATA_TAB_1, data))

#Unpack Ethernet frame 
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] # rest of data 

#Return properly formatted MAC address (like AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4 # Bitwise operations to get only the version for version and header len block
    header_length = (version_header_length & 15) * 4 # To get only lower bits
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:] # return data after the header

#Return properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

#Unpack ICMP packet
def unpack_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:] 

#Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    urg = (offset_reserved_flags & 32) >> 5
    ack = (offset_reserved_flags & 16) >> 4
    psh = (offset_reserved_flags & 8) >> 3
    rst = (offset_reserved_flags & 4) >> 2
    syn = (offset_reserved_flags & 2) >> 1
    fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, urg, ack, psh, rst, syn, fin, data[offset:] 

#Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

#Format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()
