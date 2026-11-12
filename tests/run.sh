#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# End-to-end tests for specchio.  Needs: python3, socat, unprivileged user
# namespaces.  Usage: tests/run.sh [path/to/specchio]

set -eu

TESTS="$(cd "$(dirname "$0")" && pwd)"
B="${1:-${TESTS}/../target/release/specchio}"
TMP="$(mktemp -d)"
PIDS=""
trap 'for p in ${PIDS}; do kill "${p}" 2>/dev/null || :; done; rm -rf "${TMP}"' EXIT
fail=0

check() {
	name="$1"; shift
	if "$@" >"${TMP}/out" 2>&1; then
		echo "PASS ${name}"
	else
		echo "FAIL ${name}"; sed 's/^/    /' "${TMP}/out"; fail=1
	fi
}

socat UNIX-LISTEN:"${TMP}/echo.sock",fork EXEC:cat 2>/dev/null & PIDS="${PIDS} $!"
socat ABSTRACT-LISTEN:specchio-test-$$,fork EXEC:cat 2>/dev/null & PIDS="${PIDS} $!"
python3 "${TESTS}/bulk_server.py" "${TMP}/bulk.sock" 50000000 & PIDS="${PIDS} $!"
sleep 0.5

check "echo, IPv4" sh -c "'${B}' -T 8000:'${TMP}/echo.sock' -- \
	sh -c 'echo hi | socat -t1 - TCP:127.0.0.1:8000' | grep -qx hi"

check "echo, IPv6" sh -c "'${B}' -T 8000:'${TMP}/echo.sock' -- \
	sh -c 'echo hi | socat -t1 - TCP:[::1]:8000' | grep -qx hi"

check "echo, abstract socket" sh -c "'${B}' -T 127.0.0.1/8000:@specchio-test-$$ -- \
	sh -c 'echo hi | socat -t1 - TCP:127.0.0.1:8000' | grep -qx hi"

check "bulk, 20 x 50 MB each way, half-close" timeout 60 \
	"${B}" -T 3128:"${TMP}/bulk.sock" -- \
	python3 "${TESTS}/bulk_client.py" 3128 50000000 20

# socat's listen backlog is 5: exercises connect() retries
check "500 short connections, 50 concurrent" timeout 60 \
	"${B}" -T 8000:@specchio-test-$$ -- python3 -c '
import socket, sys, concurrent.futures as cf
def one(i):
    s = socket.create_connection(("127.0.0.1", 8000)); m = f"msg {i}".encode()
    s.sendall(m); s.shutdown(socket.SHUT_WR); r = b""
    while (b := s.recv(100)): r += b
    return r == m
with cf.ThreadPoolExecutor(50) as ex: sys.exit(0 if all(ex.map(one, range(500))) else 1)'

check "missing target resets connection" "${B}" -T 8000:"${TMP}/none.sock" -- python3 -c '
import socket
s = socket.create_connection(("127.0.0.1", 8000))
try: s.recv(1)
except ConnectionResetError: pass
else: raise SystemExit(1)'

check "exit status passed through" sh -c "'${B}' -- sh -c 'exit 7'; test \$? -eq 7"

check "no descriptors leaked to command" sh -c "'${B}' -T 8000:'${TMP}/echo.sock' -- \
	sh -c 'ls /proc/self/fd' | sort -n | tr '\n' ' ' | grep -qx '0 1 2 3 '"

exit ${fail}
