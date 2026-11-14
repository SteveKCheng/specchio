# Host side UDP server: bind each ADDR:PORT given as argument.  Reply to each
# datagram with the local address it arrived on ("ADDR PORT\n"), followed by
# the datagram itself.
import socket, sys, threading

def serve(srv):
    addr, port = srv.getsockname()[:2]
    head = f"{addr} {port}\n".encode()
    while True:
        b, peer = srv.recvfrom(1 << 16)
        srv.sendto(head + b, peer)

threads = []
for spec in sys.argv[1:]:
    addr, port = spec.rsplit(":", 1)
    addr = addr.strip("[]")
    af = socket.AF_INET6 if ":" in addr else socket.AF_INET
    srv = socket.socket(af, socket.SOCK_DGRAM)
    if af == socket.AF_INET6:
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    srv.bind((addr, int(port)))
    threads.append(threading.Thread(target=serve, args=(srv,), daemon=True))
[t.start() for t in threads]
print("ready", flush=True)
threading.Event().wait()
