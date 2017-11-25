#!/usr/bin/env python
from socket import *

def tcp_ipv6():
    HOST = "2804:14d:4c93:175b:43b:541b:c474:466c"
    PORT = 21567
    ADDR = (HOST, PORT)
    BUFSIZ = 1024
    
    sock = socket(AF_INET6, SOCK_STREAM)
    sock.connect(ADDR)

    while True:
        data = raw_input('> ') 
        if not data:
            break
        sock.send(data)
        response = sock.recv(BUFSIZ)
        if not response:
            break
        print(response.decode('utf-8'))
    sock.close()        
    
tcp_ipv6()
