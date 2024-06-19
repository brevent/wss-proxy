import socket
import sys

host = '127.0.0.1'
port = int(len(sys.argv) > 1 and sys.argv or '1235')

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_socket.bind((host, port))

while True:
    data, addr = server_socket.recvfrom(65535)
    server_socket.sendto(data, addr)
