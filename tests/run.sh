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
python3 "${TESTS}/bulk_server.py" tcp:127.0.0.1:18500 50000000 & PIDS="${PIDS} $!"
python3 "${TESTS}/tcp_server.py" 0.0.0.0:18000 [::]:18000 0.0.0.0:19000 [::]:19000 \
	>/dev/null & PIDS="${PIDS} $!"
sleep 0.5

# Connect to ADDR PORT in the sandbox, check echo and host address reached
tcp() {
	expect="$1"; addr="$2"; port="$3"; shift 3
	out="$("${B}" "$@" -- python3 "${TESTS}/tcp_client.py" "${addr}" "${port}" 2>&1)"
	[ "${out}" = "${expect}" ] || { echo "got: ${out}"; return 1; }
}

check "echo, IPv4" sh -c "'${B}' -T 8000:'${TMP}/echo.sock' -- \
	sh -c 'echo hi | socat -t1 - TCP:127.0.0.1:8000' | grep -qx hi"

check "echo, IPv6" sh -c "'${B}' -T 8000:'${TMP}/echo.sock' -- \
	sh -c 'echo hi | socat -t1 - TCP:[::1]:8000' | grep -qx hi"

check "echo, abstract socket" sh -c "'${B}' -T 8000:@specchio-test-$$ -- \
	sh -c 'echo hi | socat -t1 - TCP:127.0.0.1:8000' | grep -qx hi"

check "bulk, 20 x 50 MB each way, half-close" timeout 60 \
	"${B}" -T 3128:"${TMP}/bulk.sock" -- \
	python3 "${TESTS}/bulk_client.py" 3128 50000000 20

check "TCP, same loopback address" tcp "127.0.0.5 18000" 127.0.0.5 18000 -T 18000
check "TCP, IPv6 loopback" tcp "::1 18000" ::1 18000 -T 18000
check "TCP, other port" tcp "127.0.0.1 19000" 127.0.0.1 18000 -T 18000:19000
check "TCP, target address" tcp "::1 18000" 127.0.0.1 18000 -T 18000:::1
check "TCP, target address and port" tcp "127.0.0.1 19000" ::1 80 -T 80:127.0.0.1/19000
check "TCP, several -T" tcp "::1 19000" 127.0.0.1 3000 -T 2000 -T 3000:::1/19000

check "TCP, pasta-style options" tcp "127.0.0.1 18000" 127.0.0.1 18000 \
	-t none -u none -U none --tcp-ports=none --udp-ports=none --udp-ns=none \
	-T none -T 18000

check "auto and all rejected" sh -c "! '${B}' -T auto -- true && ! '${B}' -t all -- true"

check "TCP, refused port resets connection" sh -c "'${B}' -T 18000:20000 -- \
	python3 '${TESTS}/tcp_client.py' 127.0.0.1 18000 2>&1 | grep -q ConnectionResetError"

check "TCP, non-local target address rejected" sh -c "! '${B}' -T 18000:198.51.100.7 -- true"

check "TCP, bulk, 20 x 50 MB each way, half-close" timeout 60 \
	"${B}" -T 3128:18500 -- python3 "${TESTS}/bulk_client.py" 3128 50000000 20

# A host with a non-loopback interface: simulate one in an outer namespace
if unshare -Urn sh -c 'ip link add dummy0 type dummy' 2>/dev/null; then
	check "TCP, address of non-loopback host interface" unshare -Urn sh -c "
		ip link set lo up; ip link add dummy0 type dummy; ip link set dummy0 up
		ip addr add 192.0.2.1/24 dev dummy0
		python3 '${TESTS}/tcp_server.py' 192.0.2.1:18000 >/dev/null & sleep 0.5
		out=\$('${B}' -T 8000:192.0.2.1/18000 -- \
			python3 '${TESTS}/tcp_client.py' 127.0.0.1 8000)
		kill %1; test \"\${out}\" = '192.0.2.1 18000'"
else
	echo "SKIP TCP, address of non-loopback host interface (no dummy interfaces)"
fi

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
