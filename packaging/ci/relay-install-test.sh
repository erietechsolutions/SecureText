#!/bin/sh
# Install the relay package on a clean supported host (a container is
# fine), check the binary is static and runs, the systemd unit is valid for
# this host's systemd, and it uninstalls cleanly. Usage:
#   relay-install-test.sh path/to/securetext-relay.{deb,rpm}
set -eu
pkg="$1"
case "$pkg" in
    *.deb)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "$pkg" systemd >/dev/null
        unit=/lib/systemd/system/securetext-relay.service
        remove() { apt-get remove -y -qq securetext-relay >/dev/null; }
        ;;
    *.rpm)
        dnf install -y -q "$pkg" systemd
        unit=/usr/lib/systemd/system/securetext-relay.service
        remove() { dnf remove -y -q securetext-relay; }
        ;;
    *) echo "not a .deb or .rpm: $pkg" >&2; exit 2 ;;
esac
. /etc/os-release
echo "== $PRETTY_NAME, systemd $(systemctl --version | head -1 | cut -d' ' -f2)"
# Static: no interpreter, no shared libraries, whatever glibc/OpenSSL
# this host has.
if grep -q "ld-linux" /usr/bin/securetext-relay; then
    echo "securetext-relay is dynamically linked" >&2
    exit 1
fi
securetext-relay --version
test -f "$unit"
# Unknown directives only warn (older systemd); real errors fail.
out=$(systemd-analyze verify "$unit" 2>&1 || true)
echo "$out"
if echo "$out" | grep -Ei "failed|invalid|bad-setting|executable path is not absolute|not executable"; then
    exit 1
fi
# The relay starts and runs (it keeps trying to reach Tor if it can't).
dir=$(mktemp -d)
securetext-relay --dir "$dir" >"$dir/log" 2>&1 &
pid=$!
sleep 10
if ! kill -0 "$pid" 2>/dev/null; then
    echo "the relay exited early:" >&2
    cat "$dir/log" >&2
    exit 1
fi
kill "$pid"
remove
test ! -e /usr/bin/securetext-relay
echo "== OK: $PRETTY_NAME"
