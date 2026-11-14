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
python3 "${TESTS}/udp_server.py" 127.0.0.1:18000 127.0.0.5:18000 [::1]:18000 \
	127.0.0.1:19000 [::1]:19000 127.0.0.1:19001 >/dev/null & PIDS="${PIDS} $!"
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

check "TCP, list" tcp "::1 19000" 127.0.0.1 3001 -T 3000,3001:::1/19000
check "TCP, range" tcp "127.0.0.1 19000" 127.0.0.1 3005 -T 2995-3005:18990-19000
check "TCP, range with exclusion" tcp "127.0.0.1 18000" 127.0.0.1 18000 \
	-T 17990-18010,~18005,~17995-17999
check "TCP, excluded port not forwarded" sh -c "'${B}' -T 17990-18010,~18005 -- \
	python3 '${TESTS}/tcp_client.py' 127.0.0.1 18005 2>&1 | grep -q ConnectionRefusedError"
check "exclusions only rejected" sh -c "! '${B}' -U ~80 -- true 2>'${TMP}/err' &&
	grep -q 'by design' '${TMP}/err'"
check "overlapping ports rejected" sh -c "! '${B}' -T 80-90 -T 85 -- true 2>'${TMP}/err' &&
	grep -q 'TCP port 85 in namespace forwarded twice' '${TMP}/err'"

# More than the maximum number of descriptors per SCM_RIGHTS message (253)
check "3000 TCP and 2999 UDP ports" "${B}" -T 10000-12999:15001-18000 \
	-U 10000-12999,~11000 -- sh -c "
	test \$(tail -n +2 /proc/net/tcp6 | wc -l) -eq 3000 &&
	test \$(tail -n +2 /proc/net/udp6 | wc -l) -eq 2999 &&
	python3 '${TESTS}/tcp_client.py' 127.0.0.1 12999 | grep -qx '127.0.0.1 18000' &&
	! python3 '${TESTS}/tcp_client.py' 127.0.0.1 13000 2>/dev/null"

# Send datagrams to ADDR PORT in the sandbox, check replies and host address
udp() {
	expect="$1"; addr="$2"; port="$3"; shift 3
	out="$("${B}" "$@" -- python3 "${TESTS}/udp_client.py" "${addr}" "${port}" 2>&1)"
	[ "${out}" = "${expect}" ] || { echo "got: ${out}"; return 1; }
}

check "UDP, same loopback address" udp "127.0.0.5 18000" 127.0.0.5 18000 -U 18000
check "UDP, IPv6 loopback" udp "::1 18000" ::1 18000 -U 18000
check "UDP, other port" udp "127.0.0.1 19000" 127.0.0.1 18000 -U 18000:19000
check "UDP, target address" udp "::1 18000" 127.0.0.1 18000 -U 18000:::1
check "UDP, target address and port" udp "127.0.0.1 19000" ::1 53 -U 53:127.0.0.1/19000
check "UDP, host name" sh -c "'${B}' -U 53:localhost/19000 -- \
	python3 '${TESTS}/udp_client.py' 127.0.0.1 53 | grep -Eqx '(127.0.0.1|::1) 19000'"
check "UDP, list and range" udp "127.0.0.1 19001" 127.0.0.1 5001 -U 80,5000-5001:19000-19001
check "UDP, with TCP on the same port" sh -c "'${B}' -T 18000 -U 18000:19000 -- sh -c \
	\"python3 '${TESTS}/tcp_client.py' 127.0.0.1 18000 &&
	  python3 '${TESTS}/udp_client.py' 127.0.0.1 18000\" |
	tr '\n' ' ' | grep -qx '127.0.0.1 18000 127.0.0.1 19000 '"
check "UDP, 200 datagrams of 60000 bytes, IPv4" sh -c "'${B}' -U 18000:19000 -- \
	python3 '${TESTS}/udp_client.py' 127.0.0.1 18000 200 60000 | grep -qx '127.0.0.1 19000'"
check "UDP, 200 datagrams of 65000 bytes, IPv6" sh -c "'${B}' -U 18000:19000 -- \
	python3 '${TESTS}/udp_client.py' ::1 18000 200 65000 | grep -qx '::1 19000'"
check "UDP, 100 concurrent flows" "${B}" -U 18000 -- python3 -c '
import socket
ss = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for i in range(100)]
for i, s in enumerate(ss):
    s.bind(("", 0)); s.settimeout(5); s.sendto(str(i).encode(), ("127.0.0.1", 18000))
for i, s in enumerate(ss):
    assert s.recv(100) == f"127.0.0.1 18000\n{i}".encode()'
check "UDP, refused port: no reply, specchio carries on" sh -c "'${B}' -d -U 18001 -U 18000 -- \
	sh -c \"! python3 '${TESTS}/udp_client.py' 127.0.0.1 18001 2>/dev/null &&
	  python3 '${TESTS}/udp_client.py' 127.0.0.1 18000\" 2>'${TMP}/err' | grep -qx '127.0.0.1 18000' &&
	grep -q 'UDP flow 0: Connection refused' '${TMP}/err'"
check "UDP, Unix domain socket target rejected" sh -c "! '${B}' -U 53:/run/dns.sock -- true"

check "TCP, refused port resets connection" sh -c "'${B}' -T 18000:20000 -- \
	python3 '${TESTS}/tcp_client.py' 127.0.0.1 18000 2>&1 | grep -q ConnectionResetError"

check "TCP, host name" sh -c "'${B}' -T 8000:localhost/18000 -- \
	python3 '${TESTS}/tcp_client.py' 127.0.0.1 8000 | grep -Eqx '(127.0.0.1|::1) 18000'"

# In a new network namespace, so that no DNS queries leave the machine
check "unresolvable host name rejected at start-up" unshare -Urn sh -c "
	! '${B}' -T 8000:nonexistent.invalid -- true 2>'${TMP}/err' &&
	grep -q \"cannot resolve 'nonexistent.invalid'\" '${TMP}/err'"

check "hint for Unix socket name without ./" unshare -Urn sh -c "cd '${TMP}' &&
	! '${B}' -T 8000:echo.sock -- true 2>'${TMP}/err' &&
	grep -q \"use './echo.sock'\" '${TMP}/err'"

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

# Another host, behind a veth pair, see remote.sh
remote() {
	name="$1"; shift
	check "${name}" unshare -Urnm sh "${TESTS}/remote.sh" "${B}" "${TMP}" "$@"
}
remote_udp() {
	name="$1"; shift
	check "${name}" env PROTO=udp unshare -Urnm sh "${TESTS}/remote.sh" "${B}" "${TMP}" "$@"
}

if unshare -Urn sh -c 'ip link add veth0 type veth peer name veth1' 2>/dev/null; then
	remote "TCP, other host" "" 198.51.100.2/18000 "198.51.100.2 18000"
	remote "TCP, other host by name" "198.51.100.2 remote.test\\n" \
		remote.test/18000 "198.51.100.2 18000" "remote.test resolves to 198.51.100.2$"
	remote "TCP, other host by name, first address refused" \
		"198.51.100.3 remote.test\\n198.51.100.2 remote.test\\n" \
		remote.test/18000 "198.51.100.2 18000" \
		"198.51.100.3:18000: Connection refused.*trying next address"
	remote "TCP, no route to other host resets connection" "" 203.0.113.1/18000 "" \
		"cannot connect to 203.0.113.1:18000: Network is unreachable" \
		"ConnectionResetError"
	remote_udp "UDP, other host by name" "198.51.100.2 remote.test\\n" \
		remote.test/18000 "198.51.100.2 18000" "UDP flow 0: .* -> 198.51.100.2:18000 on host"
	remote_udp "UDP, no route to other host" "" 203.0.113.1/18000 "" \
		"cannot connect to 203.0.113.1:18000: Network is unreachable" "TimeoutError"
else
	echo "SKIP TCP, other host (no veth interfaces)"
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

# Inherited descriptors go to the command, and the parent doesn't keep them
check "inherited files: passed on, not kept" sh -c "
	touch '${TMP}/marker'
	'${B}' -T 18000 -- sh -c 'test -e /proc/self/fd/5 && test -e /proc/self/fd/9 &&
		touch ${TMP}/ok; sleep 1' 5<'${TMP}/marker' 9<'${TMP}/marker' & pid=\$!
	sleep 0.5; fds=\$(ls -l /proc/\${pid}/fd); wait \${pid}
	test -e '${TMP}/ok' && ! echo \"\${fds}\" | grep -q marker &&
	test \"\$(readlink /proc/\${pid}/fd/1 2>/dev/null || echo gone)\" != '${TMP}/marker'"

check "reader sees EOF when command closes standard output" sh -c "
	start=\$(date +%s%N)
	'${B}' -- sh -c 'echo line; exec >&-; sleep 2' |
		{ cat >/dev/null; echo \$(( (\$(date +%s%N) - start) / 1000000 )) > '${TMP}/eof_ms'; }
	test \$(cat '${TMP}/eof_ms') -lt 1000"

check "command runs with original IDs, without capabilities" sh -c "'${B}' -- sh -c '
	test \$(id -u) = $(id -u) && test \$(id -g) = $(id -g) &&
	grep -q \"^CapEff:[[:space:]]*0*\$\" /proc/self/status && ! ip link set lo down 2>/dev/null'"
check "command can bind ports below 1024 and use ping sockets" "${B}" -- python3 -c '
import socket
socket.socket(socket.AF_INET).bind(("127.0.0.1", 80))
socket.socket(socket.AF_INET6).bind(("::1", 443))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
s.settimeout(5); s.sendto(b"\x08\0\0\0\0\0\0\0", ("127.0.0.1", 0)); s.recv(100)
socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)'
check "--root: command runs as root" sh -c "'${B}' --root -- sh -c '
	test \$(id -u) = 0 && ip link set lo down'"
check "started as root: command stays root" unshare -r sh -c "'${B}' -- sh -c '
	test \$(id -u) = 0 && ip link set lo down'"

# Run "specchio OPTION... -- sh -c SCRIPT" in the background, as SPID, with
# SIGINT and SIGQUIT not ignored (unlike in background jobs), and wait until
# SCRIPT touches the file given as $0
sig_spawn() {
	script="$1"; shift
	rm -f "${TMP}/ready" "${TMP}/log"
	env --default-signal=INT,QUIT "${B}" "$@" -- sh -c "${script}" "${TMP}/ready" &
	SPID=$!
	i=0; until [ -e "${TMP}/ready" ]; do
		i=$((i + 1)); [ ${i} -lt 200 ] || return 1; sleep 0.05
	done
}

# Forwarded signals: the command handles them, and shuts down slowly on
# SIGTERM, using a forwarded port, while specchio keeps running
sig_forward() {
	sig_spawn '
	for s in HUP INT QUIT USR1 USR2; do trap "echo ${s} >> $0.log" ${s}; done
	trap "sleep 0.5; echo hi | socat -t1 - TCP:127.0.0.1:8000 >> $0.log; exit 42" TERM
	touch "$0"; while :; do sleep 0.1; done' -T 8000:"${TMP}/echo.sock" || return 1
	for s in HUP INT QUIT USR1 USR2 TERM; do kill -s ${s} "${SPID}"; sleep 0.3; done
	r=0; wait "${SPID}" || r=$?
	[ ${r} -eq 42 ] || { echo "exit status ${r}"; return 1; }
	[ "$(tr '\n' ' ' < "${TMP}/ready.log")" = "HUP INT QUIT USR1 USR2 hi " ] ||
		{ cat "${TMP}/ready.log"; return 1; }
}
check "signals: forwarded, specchio runs until the command exits" sig_forward

sig_unhandled() {
	sig_spawn 'touch "$0"; while :; do sleep 0.1; done' || return 1
	kill -s USR1 "${SPID}"
	r=0; wait "${SPID}" || r=$?
	[ ${r} -eq $((128 + 10)) ] || { echo "exit status ${r}"; return 1; }
}
check "signals: command killed by forwarded signal, status passed through" sig_unhandled

# Ignored signals stay ignored, as with nohup
sig_ignored() {
	rm -f "${TMP}/ready"
	sh -c "trap '' HUP; exec '${B}' -- sh -c 'trap \"exit 3\" TERM; touch \"\$0\"
		while :; do sleep 0.1; done' '${TMP}/ready'" & SPID=$!
	i=0; until [ -e "${TMP}/ready" ]; do
		i=$((i + 1)); [ ${i} -lt 200 ] || return 1; sleep 0.05
	done
	kill -s HUP "${SPID}"; sleep 0.3; kill -s TERM "${SPID}"
	r=0; wait "${SPID}" || r=$?
	[ ${r} -eq 3 ] || { echo "exit status ${r}"; return 1; }
}
check "signals: ignored on entry, not forwarded" sig_ignored

# The terminal sends Ctrl-C and Ctrl-\ to the command already: once is enough
check "signals: from the terminal, not forwarded" sh -c "
	python3 '${TESTS}/terminal.py' '\\x03\\x1c' '${B}' -- sh -c '
		trap \"echo INT >> ${TMP}/tty.log\" INT; trap \"exit 5\" QUIT
		while :; do sleep 0.1; done' | grep -qx 5 &&
	test \"\$(cat '${TMP}/tty.log')\" = INT &&
	python3 '${TESTS}/terminal.py' '\\x03' '${B}' -- sleep 30 | grep -qx 130"

check "SIGKILL to specchio kills the command" sh -c "
	'${B}' -- sh -c 'echo \$\$ > ${TMP}/cmd.pid; exec sleep 30' & pid=\$!
	until [ -s '${TMP}/cmd.pid' ]; do sleep 0.05; done; sleep 0.2
	kill -s KILL \${pid}; sleep 0.3; ! kill -0 \$(cat '${TMP}/cmd.pid') 2>/dev/null"

check "exit status passed through" sh -c "'${B}' -- sh -c 'exit 7'; test \$? -eq 7"

check "no descriptors leaked to command" sh -c "'${B}' -T 8000:'${TMP}/echo.sock' -U 53 \
	-t 28000 -- sh -c 'ls /proc/self/fd' | sort -n | tr '\n' ' ' | grep -qx '0 1 2 3 '"

# Run "specchio OPTION... -- SERVER [ARG]..." in the background, as SPID, and
# wait until something accepts connections on 127.0.0.1 port 8000 in there,
# or, with PROBE=udp, replies to datagrams sent there.  The server is the
# command itself, so that it can't outlive specchio
serve() {
	opts=""; while [ "$1" != -- ]; do opts="${opts} $1"; shift; done; shift
	rm -f "${TMP}/ready"
	if [ "${PROBE:-tcp}" = udp ]; then
		probe='s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.2)
s.bind(("", 0)); s.sendto(b"probe", ("127.0.0.1", 8000)); s.recv(100)'
	else
		probe='socket.create_connection(("127.0.0.1", 8000))'
	fi
	# shellcheck disable=SC2086
	"${B}" ${opts} -- sh -c '{ i=0; until python3 -c "import socket
$1" 2>/dev/null; do i=$((i + 1)); [ ${i} -lt 200 ] || exit 1; sleep 0.05; done
		touch "$0"; } & shift; exec "$@"' "${TMP}/ready" "${probe}" "$@" >/dev/null &
	SPID=$!
	i=0; until [ -e "${TMP}/ready" ]; do
		i=$((i + 1)); [ ${i} -lt 200 ] || { kill "${SPID}"; return 1; }; sleep 0.05
	done
}

# Connect to ADDR PORT on the host, forwarded into the sandbox, with a server
# on 0.0.0.0 and [::] port 8000 in there, check echo and address reached, or
# the last line of the client's error
tin() {
	expect="$1"; addr="$2"; port="$3"; shift 3
	serve "$@" -- python3 "${TESTS}/tcp_server.py" 0.0.0.0:8000 [::]:8000 || return 1
	out="$(python3 "${TESTS}/tcp_client.py" "${addr}" "${port}" 2>&1 | tail -n 1)"
	kill "${SPID}"; wait "${SPID}" || :
	[ "${out}" = "${expect}" ] || { echo "got: ${out}"; return 1; }
}

check "TCP in, same loopback address" tin "127.0.0.5 8000" 127.0.0.5 28000 -t 28000:8000
check "TCP in, IPv6 loopback" tin "::1 8000" ::1 28000 -t 28000:8000
check "TCP in and out, long option names" tin "127.0.0.1 8000" 127.0.0.1 28000 \
	--in-tcp 28000:8000 --out-tcp=18000 --in-udp=28000 --out-udp 18000
check "TCP in, listening address" tin "127.0.0.1 8000" 127.0.0.1 28000 \
	-t 127.0.0.1/28000:8000
check "TCP in, other address: refused on host" tin \
	"ConnectionRefusedError: [Errno 111] Connection refused" ::1 28000 -t 127.0.0.1/28000:8000
check "TCP in, target address of other version" tin "127.0.0.2 8000" ::1 28000 \
	-t 28000:127.0.0.2/8000
check "TCP in, range" tin "127.0.0.1 8000" 127.0.0.1 28000 -t 27995-28005:7995-8005
check "TCP in, with outbound forwards" tin "127.0.0.1 8000" 127.0.0.1 28000 \
	-T 18000 -U 18000 -t 28001,28000:8000 -T 28000
check "TCP in, refused port resets connection" tin \
	"ConnectionResetError: [Errno 104] Connection reset by peer" 127.0.0.1 28000 -t 28000:8001

check "TCP in, port in use on host: command not run" sh -c "
	! '${B}' -t 18000 -- touch '${TMP}/ran' 2>'${TMP}/err' && ! test -e '${TMP}/ran' &&
	grep -q 'cannot listen on TCP port 18000 at \\* on the host' '${TMP}/err'"

tin_bulk() {
	serve -t 28500:8000 -- python3 "${TESTS}/bulk_server.py" tcp:127.0.0.1:8000 50000000 ||
		return 1
	r=0; timeout 60 python3 "${TESTS}/bulk_client.py" 28500 50000000 20 || r=1
	kill "${SPID}"; wait "${SPID}" || :
	return ${r}
}
check "TCP in, bulk, 20 x 50 MB each way, half-close" tin_bulk

# Pools of sockets in the namespace are refilled, and specchio is left with a
# single thread
tin_many() {
	# With socat's default backlog of 5, the kernel resets some connections
	serve -t 28000:8000 -- socat TCP-LISTEN:8000,fork,reuseaddr,backlog=128 EXEC:cat ||
		return 1
	r=0; timeout 60 python3 -c '
import socket, sys, concurrent.futures as cf
def one(i):
    s = socket.create_connection(("127.0.0.1", 28000)); m = f"msg {i}".encode()
    s.sendall(m); s.shutdown(socket.SHUT_WR); r = b""
    while (b := s.recv(100)): r += b
    return r == m
with cf.ThreadPoolExecutor(50) as ex: sys.exit(0 if all(ex.map(one, range(500))) else 1)' || r=1
	grep -q "^Threads:[[:space:]]*1$" "/proc/${SPID}/status" || { echo "threads left"; r=1; }
	kill "${SPID}"; wait "${SPID}" || :
	return ${r}
}
check "TCP in, 500 short connections, 50 concurrent" tin_many

# Send datagrams to ADDR PORT on the host, forwarded into the sandbox, with a
# server on 127.0.0.1, 127.0.0.2, 127.0.0.5 and ::1 port 8000 in there, check
# replies and the address reached, or the last line of the client's error
uin() {
	expect="$1"; addr="$2"; port="$3"; shift 3
	PROBE=udp serve "$@" -- python3 "${TESTS}/udp_server.py" 127.0.0.1:8000 127.0.0.2:8000 \
		127.0.0.5:8000 [::1]:8000 || return 1
	out="$(python3 "${TESTS}/udp_client.py" "${addr}" "${port}" ${COUNT:-} ${SIZE:-} 2>&1 |
		tail -n 1)"
	kill "${SPID}"; wait "${SPID}" || :
	[ "${out}" = "${expect}" ] || { echo "got: ${out}"; return 1; }
}

check "UDP in, same loopback address" uin "127.0.0.5 8000" 127.0.0.5 28000 -u 28000:8000
check "UDP in, IPv6 loopback" uin "::1 8000" ::1 28000 -u 28000:8000
check "UDP in, listening and target address" uin "127.0.0.2 8000" 127.0.0.1 28000 \
	-u 127.0.0.1/28000:127.0.0.2/8000
check "UDP in, other address: no reply" uin "TimeoutError: timed out" ::1 28000 \
	-u 127.0.0.1/28000:8000
check "UDP in, range, with TCP and outbound forwards" uin "127.0.0.1 8000" 127.0.0.1 28000 \
	-u 27990-28000:7990-8000 -t 28000 -T 18000 -U 18000 -U 8001
uin_big() {
	COUNT=200; SIZE=65000; r=0
	uin "::1 8000" ::1 28000 -u 28000:8000 || r=1
	unset COUNT SIZE; return ${r}
}
check "UDP in, 200 datagrams of 65000 bytes, IPv6" uin_big

uin_flows() {
	PROBE=udp serve -u 28000:8000 -- python3 "${TESTS}/udp_server.py" 127.0.0.1:8000 ||
		return 1
	r=0; python3 -c '
import socket
ss = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for i in range(100)]
for i, s in enumerate(ss):
    s.bind(("", 0)); s.settimeout(5); s.sendto(str(i).encode(), ("127.0.0.1", 28000))
for i, s in enumerate(ss):
    assert s.recv(100) == f"127.0.0.1 8000\n{i}".encode()' || r=1
	grep -q "^Threads:[[:space:]]*1$" "/proc/${SPID}/status" || { echo "threads left"; r=1; }
	kill "${SPID}"; wait "${SPID}" || :
	return ${r}
}
check "UDP in, 100 concurrent flows" uin_flows

# specchio joined the user namespace of the sandbox, where the command is root
check "TCP in, --root: command can't take descriptors from specchio or trace it" \
	"${B}" --root -t 28000 -- python3 -c '
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
assert os.getuid() == 0
pfd = os.pidfd_open(os.getppid())
for fd in range(3, 64):
    assert libc.syscall(438, pfd, fd, 0) < 0 and ctypes.get_errno() == 1, fd  # pidfd_getfd
assert libc.ptrace(16, os.getppid(), 0, 0) < 0 and ctypes.get_errno() == 1  # PTRACE_ATTACH'

exit ${fail}
