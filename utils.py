from subprocess import Popen, PIPE
from fm import *
from uuid import getnode
import re
import socket
def getMyInterfaceName():
	return "wlp1s0"
	
def getMacDefaultGateway():
	return getMacByIPv4( get_default_gateway_ip_linux() )

def getLocalMac():
	return ih12(getnode())

def getLocalIPv4():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	local_ip = s.getsockname()[0]
	s.close()
	return local_ip

def getMacByIPv4(IP):
	Popen(["ping", "-c 1", IP], stdout = PIPE)
	pid = Popen(["arp", "-n", IP], stdout = PIPE)
	s = pid.communicate()[0]
	search = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s)
	if( search == None ):
		return "NO MAC FOUND"
	mac = search.groups()[0]
	#return mac 		#hexstring formatada
	return mac.replace(':','') #hexstring pura
	
	
def get_default_iface_name_linux():
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, _, flags, _, _, _, _, _, _, _, =  line.strip().split()
                if dest != '00000000' or not int(flags, 16) & 2:
                    continue
                return iface
            except:
                continue
                
def get_default_gateway_ip_linux():
	reversedHex = get_reversed_gateway_ip()
	newip = reversedHex[6:8]+reversedHex[4:6]+reversedHex[2:4]+reversedHex[0:2]
	return hextoip(newip)

def get_reversed_gateway_ip():
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, gateway, flags, _, _, _, _, _, _, _, =  line.strip().split()
                if dest != '00000000' or not int(flags, 16) & 2:
                    continue
                return gateway
            except:
                continue
