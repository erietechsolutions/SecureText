#!/usr/bin/env bash
# Build the relay as one static x86_64 musl binary and package it as a
# .deb and an .rpm. A static binary has no glibc or OpenSSL dependency, so
# the same packages install on every supported relay host
# (docs/platform-support.md): Ubuntu Server 20.04+, Ubuntu Desktop 22.04+,
# Debian 13+ and Fedora 44+.
#
# Needs: rustup, musl-gcc (Debian/Ubuntu: musl-tools; Fedora: musl-gcc),
# perl and make (OpenSSL is built from source), cargo-deb, cargo-generate-rpm.
set -euo pipefail
cd "$(dirname "$0")/.."
target=x86_64-unknown-linux-musl
rustup target add "$target"
export CC_x86_64_unknown_linux_musl=musl-gcc
cargo build --release --locked --target "$target" -p securetext-relay --features static
tdir="${CARGO_TARGET_DIR:-target}"
bin="$tdir/$target/release/securetext-relay"
if ldd "$bin" 2>&1 | grep -q "=>"; then
    echo "$bin is dynamically linked" >&2
    exit 1
fi
cargo deb --no-build --target "$target" -p securetext-relay
cargo generate-rpm --target "$target" -p crates/securetext-relay
ls -l "$tdir/$target"/debian/*.deb "$tdir/$target"/generate-rpm/*.rpm
