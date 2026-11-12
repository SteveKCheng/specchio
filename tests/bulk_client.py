# Sandbox side: send N random bytes, half-close, check the echoed hash and
# the hash of what comes back.
import hashlib, os, socket, sys, threading, random
port, n, conns = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
expect = hashlib.sha256(random.Random(42).randbytes(n)).hexdigest()
ok = []
def one(i):
    s = socket.create_connection(("127.0.0.1", port))
    data = os.urandom(n)
    s.sendall(data); s.shutdown(socket.SHUT_WR)
    buf = bytearray()
    while (b := s.recv(1 << 20)): buf += b
    line, rest = bytes(buf).split(b"\n", 1)
    ok.append(line.decode() == hashlib.sha256(data).hexdigest() and
              hashlib.sha256(rest).hexdigest() == expect)
ts = [threading.Thread(target=one, args=(i,)) for i in range(conns)]
[t.start() for t in ts]; [t.join() for t in ts]
print(f"{sum(ok)}/{conns} connections OK"); sys.exit(0 if all(ok) and len(ok) == conns else 1)
