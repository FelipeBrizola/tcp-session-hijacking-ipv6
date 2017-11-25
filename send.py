import socket
import utils
from fm import *

my_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

def checksum(msg):
	su = 0	

	for i in range (0, len(msg),2):
		
	        w = (ord(msg[i]) << 8) + (ord(msg[i+1]))
		su = su + w

	su = (su >> 16) + (su & 0xffff)

	su = ~su & 0xffff 

	return su
def build_pseudo_header(src_ip, dest_ip, data, upper_layer_packet_length):
        zeros = '0000' # n sei quantos zeros vao nesse campo
        next_header = "06"
        pseudo_header = src_ip + dest_ip + upper_layer_packet_length + zeros + next_header 
        return pseudo_header

def build_tcp_header(src_port, dest_port, seq_no, ack_no, header_length, ack_flag, syn_flag, fin_flag, push_flag, reset_flag, urg_flag, window_size, urg_pointer, options, src_add_ip, dst_add_ip, data):
	
	tcp_flags = fin_flag + (syn_flag << 1) + (reset_flag << 2) + (push_flag << 3) + (ack_flag << 4) + (urg_flag << 5)
	tcp_checksum = '0000'

        tcp_header = src_port + dest_port + seq_no + ack_no + header_length + str(tcp_flags) + window_size + urg_pointer

	####creating pseudo header####
        pseudo_header = build_pseudo_header(src_add_ip, dst_add_ip, data, str(len(tcp_header) + len(data)))

	if (len(data) % 2 != 0):
		data = data + " "
	
	if (push_flag == 1):
	        pseudo_header = pseudo_header + tcp_header + data
	else:
		pseudo_header = pseudo_header + tcp_header

	# tcp_checksum = checksum(pseudo_header)
        tcp_checksum = "0000"

        # TCP
        print("\n## BUILDING TCP PACKET SOURCE ")
        print("## Source port = " + src_port)
        print("## Destination port = " + dest_port)
        print("## Sequence number = " + seq_no)
        print("## Acknoledgment = " + ack_no)
        print("## Header length = " + header_length)
        print("## Flags  = " + str(tcp_flags))
        print("## Window size = " + window_size)
        # print("## Checksum = " + tcp_checksum)
        print("## Urgent pointer = " + urg_pointer)
        print("## Options = " + options)

	
        tcp_header = src_port + dest_port + seq_no + ack_no + header_length + str(tcp_flags) + window_size + tcp_checksum + urg_pointer + options
	
	return tcp_header


if __name__ == "__main__":

        # ethernet
        mac_dest = "98e0d9aa8bef"
        mac_src =  "0800274bd6d3" 
        eth_type = "86dd"
        ethernet_packet = mac_dest + mac_src + eth_type

        # ipv6
        version = "60"
        flow_label = "2c45b1"
        payload_length = "0021"
        next_header = "06"
        hop_limit = "40"        
        ipv6_src = "2804014d4c93175b0000000000000004"
        ipv6_dest  = "2804014d4c93175b043b541bc474466c"
        ipv6_packet = version + flow_label + payload_length + next_header + hop_limit + ipv6_src + ipv6_dest

        # tcp
        src_port = "543f"
        dest_port = "d453"
        seq_no = "449cf497"
        ack_no = "ea1abc7d"
        header_length = "80"
        ack_flag = 0
        syn_flag = 0
        fin_flag = 0
        push_flag = 0
        reset_flag = 0
        urg_flag = 0
        window_size = "1009"
        urg_pointer = '0000'
        options = "0101080a388e15b920eaf6d2"
        data = "61"

        # Ethernet
        print("\n## BUILDING ETHERNET PACKET SOURCE ")
        print("## Src Mac          " + mac_dest)
        print("## Dest Mac         " + mac_src)
        print("## Network Protocol " + eth_type)
        
        # IPV6
        print("\n## BUILDING IPV6 PACKET SOURCE ")
        print("## Version        " + version)
        print("## flow label     " + flow_label)
        print("## Payload length " + flow_label)
        print("## Next header    " + flow_label)
        print("## Hop limit      " + flow_label)
        print("## Src Mac        " + ipv6_src)
        print("## Dest Mac       " + ipv6_dest)   

        tcp_packet = build_tcp_header(src_port, dest_port, seq_no, ack_no,header_length, 0, 0, 0, 1, 0, 0, window_size, urg_pointer, options, ipv6_src, ipv6_dest, data)

        packet = ethernet_packet + ipv6_packet + tcp_packet + data

        print packet

        my_socket.sendto(packet, ("en1", 0))
