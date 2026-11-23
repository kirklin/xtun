#!/bin/sh
# Runs a test program as root, with the directories of the system's own tools in its path. The
# jobs of `.github/workflows/ci.yml` give it to cargo as the runner of the device tests:
#
#   cargo test --config "target.'cfg(unix)'.runner = '$PWD/scripts/ci/root.sh'" --test device -- --ignored
#
# On Linux the program gets a network namespace of its own, as a container gives it in
# `scripts/linux.ts`: nothing the machine does with its own interfaces, such as the firewall rules
# of a container runtime, touches the test interfaces, and forwarding is on, which `tests/kernel.rs`
# needs. The namespace has default routes through an interface that stands for the machine's own
# network, as the tests expect of a machine, and the program gets a `/sys` of its own, which shows
# the interfaces of that namespace.

set -eu

path="/sbin:/usr/sbin:/bin:/usr/bin:/usr/pkg/sbin:/usr/pkg/bin:/usr/local/sbin:/usr/local/bin:$PATH"
if [ "$(id -u)" = 0 ]; then
    root="env"
else
    root="sudo env"
fi

if [ "$(uname -s)" = Linux ]; then
    # shellcheck disable=SC2016
    exec $root "PATH=$path" unshare --net --mount sh -c '
        set -e
        mount -t sysfs sysfs /sys
        sysctl -q -w \
            net.ipv6.conf.all.disable_ipv6=0 \
            net.ipv6.conf.default.disable_ipv6=0 \
            net.ipv4.ip_forward=1 \
            net.ipv6.conf.all.forwarding=1 \
            net.ipv4.conf.all.rp_filter=0 \
            net.ipv4.conf.default.rp_filter=0
        ip link set lo up
        ip tuntap add dev uplink mode tun
        ip link set uplink up
        ip route add default dev uplink
        ip -6 route add default dev uplink
        exec "$@"
    ' sh "$@"
fi

exec $root "PATH=$path" "$@"
