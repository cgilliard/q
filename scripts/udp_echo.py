#!/usr/bin/env python3
"""UDP echo on 127.0.0.1:PORT, for the guest's network tests (the guest reaches
the host's loopback as 10.0.2.2 under slirp)."""
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d, a)
