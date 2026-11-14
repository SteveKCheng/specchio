#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Run by run.sh in new user, network and mount namespaces (unshare -Urnm): set
# up another host, as a network namespace behind a veth pair, with addresses
# 198.51.100.2 (TCP and UDP servers on port 18000) and 198.51.100.3 (nothing
# listening), and HOSTS (printf %b format) as /etc/hosts.  Then forward port
# 8000 in a specchio sandbox to SPEC, connect to it, and check that the output
# of tcp_client.py is EXPECT, and that each PATTERN matches the output of
# specchio -d (with the client's errors).  With PROTO=udp in the environment,
# forward UDP (-U) instead, and use udp_client.py.
#
# Usage: remote.sh SPECCHIO TMPDIR HOSTS SPEC EXPECT [PATTERN]...

set -eu

TESTS="$(cd "$(dirname "$0")" && pwd)"
B="$1"; TMP="$2"; HOSTS="$3"; SPEC="$4"; EXPECT="$5"; shift 5

ip link set lo up
unshare -n sleep 60 & ns=$!
trap 'kill ${ns} ${srv:-} ${usrv:-} 2>/dev/null || :' EXIT
# Wait for the new network namespace before moving an interface into it
while [ "$(readlink /proc/${ns}/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
	sleep 0.05
done
ip link add veth0 type veth peer name veth1 netns "${ns}"
ip addr add 198.51.100.1/24 dev veth0
ip link set veth0 up
nsenter -t "${ns}" -n sh -c 'ip link set lo up; ip link set veth1 up
	ip addr add 198.51.100.2/24 dev veth1; ip addr add 198.51.100.3/24 dev veth1'
nsenter -t "${ns}" -n python3 "${TESTS}/tcp_server.py" 198.51.100.2:18000 \
	>/dev/null & srv=$!
nsenter -t "${ns}" -n python3 "${TESTS}/udp_server.py" 198.51.100.2:18000 \
	>/dev/null & usrv=$!

printf '%b' "${HOSTS}" >"${TMP}/hosts"
mount --bind "${TMP}/hosts" /etc/hosts
sleep 0.5

if [ "${PROTO:-tcp}" = udp ]; then opt=-U; else opt=-T; fi
out="$("${B}" -d "${opt}" "8000:${SPEC}" -- \
	python3 "${TESTS}/${PROTO:-tcp}_client.py" 127.0.0.1 8000 2>"${TMP}/log")" || :
[ "${out}" = "${EXPECT}" ] || { echo "got: ${out}"; cat "${TMP}/log"; exit 1; }
for p in "$@"; do
	grep -q "${p}" "${TMP}/log" || { echo "no match: ${p}"; cat "${TMP}/log"; exit 1; }
done
