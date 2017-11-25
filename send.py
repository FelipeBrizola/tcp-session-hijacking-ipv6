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
        zeros = '000000000000000000000000' # n sei quantos zeros vao nesse campo
        next_header = "06"
        return src_ip + dest_ip + upper_layer_packet_length + zeros + next_header

def build_tcp_header(src_port, dest_port, seq_no, ack_no, header_length, ack_flag, syn_flag, fin_flag, push_flag, reset_flag, urg_flag, window_size, src_add_ip, dst_add_ip, data):
	
	tcp_flags = fin_flag + (syn_flag << 1) + (reset_flag << 2) + (push_flag << 3) + (ack_flag << 4) + (urg_flag << 5)
	chk_sum = '0000'
        urg_pointer = '0000'

        tcp_header = src_port + dest_port + seq_no + ack_no + header_length + tcp_flags + window_size + urg_pointer

	####creating pseudo header####
        pseudo_header = build_pseudo_header(src_add_ip, dst_add_ip, data, len(tcp_header) + len(data))

	if (len(data) % 2 != 0):
		data = data + " "
	
	if (pshf == 1):
		pseudo_header = pseudo_header + tcp_header + data
	else:
		pseudo_header = pseudo_header + tcp_header

	tcp_checksum = checksum(pseudo_header)
	
        tcp_header = src_port + dest_port + seq_no + ack_no + header_length + tcp_flags + window + tcp_checksum + urg_pointer
	
	return tcp_header


if __name__ == "__main__":

        # ethernet
        mac_dest = "98e0d9aa8bef"
        mac_src =  "20c9d0d326d1" 
        eth_type = "86dd"
        ethernet_packet = mac_dest + mac_src + eth_type

        # ipv6
        v_plus_flow_label = "600aa2a1"
        payload = "0021"
        next_header = "06"
        hop_limit = "10"        
        ipv6_src = "2804014d4c93175b0000000000000004"
        ipv6_dest  = "2804014d4c93175b043b541bc474466c"
        ipv6_packet = v_plus_flow_label + payload + next_header + hop_limit + ipv6_src + ipv6_dest

        # tcp
        src_port = "cb44"
        dest_port = "543f"
        seq_no = "e8b205c9"
        ack_no = "20198d7c"
        window_size = "00e1"
        data = "61"
        header_length = "80"
        tcp_packet = build_tcp_header(src_port, dest_port, seq_no, ack_no, 0, 0, 0, 0, 0, 0, data, window_size, ipv6_src, ipv6_dest, data)

        packet = ethernet_packet + ipv6_packet + tcp_packet + data

        my_socket.sendto(packet.decode("hex"), ("en1", 0))
