# Host side: for each connection, hash everything until EOF, then send
# the hash followed by N bytes of deterministic data, then close.
import hashlib, os, socket, sys, threading
# Listen on a Unix socket PATH, or on TCP with tcp:ADDR:PORT
path, n = sys.argv[1], int(sys.argv[2])
if path.startswith("tcp:"):
    addr, port = path[4:].rsplit(":", 1)
    srv = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, int(port)))
else:
    try: os.unlink(path)
    except FileNotFoundError: pass
    srv = socket.socket(socket.AF_UNIX); srv.bind(path)
srv.listen(128)
def blob(n):
    import random; r = random.Random(42); return r.randbytes(n)
DATA = blob(n)
def handle(c):
    h = hashlib.sha256()
    while (b := c.recv(1 << 20)): h.update(b)
    c.sendall(h.hexdigest().encode() + b"\n" + DATA); c.close()
while True:
    c, _ = srv.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
