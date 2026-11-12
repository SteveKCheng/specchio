# Sandbox side: connect to ADDR PORT, print the address line the server sends,
# and check that a message is echoed back.
import socket, sys

addr, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((addr, port), timeout=5)
f = s.makefile("rb")
line = f.readline().decode().strip()
s.sendall(b"ping")
s.shutdown(socket.SHUT_WR)
echo = f.read()
print(line if echo == b"ping" else f"{line} BAD ECHO {echo!r}")
