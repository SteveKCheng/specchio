# Sandbox side: send COUNT (default 1) datagrams of SIZE (default 4) bytes to
# ADDR PORT, check that each reply comes from ADDR PORT and echoes the
# datagram, and print the address line of the server.
import socket, sys

addr, port = sys.argv[1], int(sys.argv[2])
count = int(sys.argv[3]) if len(sys.argv) > 3 else 1
size = int(sys.argv[4]) if len(sys.argv) > 4 else 4
af = socket.AF_INET6 if ":" in addr else socket.AF_INET
s = socket.socket(af, socket.SOCK_DGRAM)
# Bind explicitly: Python 3.14.10 returns a bogus source address from
# recvfrom() on a socket bound implicitly by sendto()
s.bind(("", 0))
s.settimeout(5)
lines = set()
for i in range(count):
    msg = (f"{i:08d}" * (size // 8 + 1))[:size].encode()
    s.sendto(msg, (addr, port))
    b, peer = s.recvfrom(1 << 16)
    if peer[:2] != (addr, port):
        sys.exit(f"reply from {peer[:2]}, expected {(addr, port)}")
    line, _, echo = b.partition(b"\n")
    if echo != msg:
        sys.exit(f"bad echo: {len(echo)} bytes, expected {len(msg)}")
    lines.add(line.decode())
print(*sorted(lines), sep="\n")
