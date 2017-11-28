#!/usr/bin/env python
from socket import *
from time import ctime
from tcp_hijack import *

HOST=''
PORT = SERVER_PORT
BUFSIZ = 1024
ADDR = (HOST, PORT)

tcpSerSock = socket(AF_INET6, SOCK_STREAM)
tcpSerSock.bind(ADDR)
tcpSerSock.listen(5)

while True:
    print('Waiting for connection...')
    tcpCliSock, addr = tcpSerSock.accept()
    print('...connected from:', addr)

    while True:
        data = tcpCliSock.recv(BUFSIZ)
        if not data:
            break
        print (data)
        tcpCliSock.send(data)
    tcpCliSock.close()
tcpSerSock.close()