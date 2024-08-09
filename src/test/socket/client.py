import socket

s1 = socket.socket()
s1.connect(('127.0.0.1', 8023))
while 1:
    send_data = input("exec > ")
    if not len(send_data.strip()) == 0:
        s1.send(send_data.encode())
        print(s1.recv(1024).decode())