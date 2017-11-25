

def ih1(value):
	return format(value, '01x')

def ih2(value):
	return format(value, '02x')
	
def ih4(value):
	return format(value, '04x')
	
def ih8(value):
	return format(value, '08x')
	
def ih12(value):
	return format(value, '012x')

def sh(value):
	return value.encode("hex")

def hi(value):
	return int(value,16)

def iptohex(IP):
	hexIP = ''
	for a in IP.split('.'):
		hexIP = hexIP + ih2(int(a))
	return hexIP
	
def hextoip(hex_data):  
	ipaddr = "%i.%i.%i.%i" % (int(hex_data[0:2],16),int(hex_data[2:4],16),int(hex_data[4:6],16),int(hex_data[6:8],16))  
	return ipaddr 