# Host side TCP server: listen on each ADDR:PORT given as argument.  For each
# connection, send the local address it arrived on ("ADDR PORT\n"), then echo
# everything back until EOF.
import socket, sys, threading

def serve(srv):
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

def handle(c):
    addr, port = c.getsockname()[:2]
    c.sendall(f"{addr} {port}\n".encode())
    while (b := c.recv(1 << 16)):
        c.sendall(b)
    c.close()

threads = []
for spec in sys.argv[1:]:
    addr, port = spec.rsplit(":", 1)
    addr = addr.strip("[]")
    af = socket.AF_INET6 if ":" in addr else socket.AF_INET
    srv = socket.socket(af)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if af == socket.AF_INET6:
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    srv.bind((addr, int(port)))
    srv.listen(128)
    threads.append(threading.Thread(target=serve, args=(srv,), daemon=True))
[t.start() for t in threads]
print("ready", flush=True)
threading.Event().wait()
