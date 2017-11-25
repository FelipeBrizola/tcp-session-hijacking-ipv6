import socket
import utils
from fm import *

def tcp_checksum(source_port, dest_port, sequence_no, ACK_no, HEADER_SIZE, FIN, ACK, data):
        # instead of concat 16-bit words, we use data that is a multiple of 16
        # (i.e. 576, the whole segment)
        all_text = str(source_port) + str(dest_port) + str(sequence_no) \
                + str(ACK_no) + str(HEADER_SIZE) + str(FIN) + str(ACK) \
                + data

        sum = 0
        for i in range((0), len(all_text) - 1, 2):
                # get unicode/byte values of operands
                first_operand = ord(all_text[i])
                second_operand = ord(all_text[i+1]) << 8

                # add
                current_sum = first_operand + second_operand
                
                # add and wrap around
                sum = ((sum + current_sum) & 0xffff) + ((sum + current_sum) >> 16)

        return sum

my_socket = socket.socket(socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(0x0003))

data = "61"


#ethernet
mac_dest = "98e0d9aa8bef"
mac_src =  "24f5aa67cf7a" #"20c9d0d326d1"#
eth_type = "86dd"
ethernet_packet = mac_dest + mac_src + eth_type

#ipv6
v_plus_flow_label = "600aa2a1"
payload = "0021"
next_header = "06"
hop_limit = "10"
ipv6_src = "2804014d4c93175b78d607723ae540ea"
#ipv6_src = "2804014d4c93175b0000000000000004"
ipv6_dest  = "2804014d4c93175b043b541bc474466c"
ipv6_packet = v_plus_flow_label + payload + next_header + hop_limit + ipv6_src + ipv6_dest

#tcp
port_src = "cb44"
port_dest = "543f"
seq_num = "e8b205c9"
ack_num = "20198d7c"
header_plus_flags = "8018"
window_size = "00e1"
check_sum = tcp_checksum(hi(port_src), hi(port_dest), hi(seq_num), hi(ack_num), 21, 0, 1, 'a')
urg_pointer = "0000"
options =  "0101080a00044eea378e5dc6"
tcp_packet = port_src + port_dest + seq_num \
        + ack_num + header_plus_flags + window_size \
        + ih4(check_sum) + urg_pointer + options

packet = ethernet_packet + ipv6_packet + tcp_packet + data

my_socket.sendto(packet.decode("hex"), ("wlp1s0", 0))

