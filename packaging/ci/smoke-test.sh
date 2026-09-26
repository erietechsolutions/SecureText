#!/usr/bin/env bash
# Start an installed SecureText under a virtual X display with a throwaway
# profile, and check it's still running after 15 seconds (it sits at the
# create-profile screen; it doesn't touch Tor until a profile is unlocked).
# Used by the release pipeline's install jobs.
set -euo pipefail
app="$1"
profile="$(mktemp -d)"
chmod 700 "$profile"
log="$(mktemp)"
# AppImages normally mount themselves with FUSE; extract instead, so this
# also works in containers.
export APPIMAGE_EXTRACT_AND_RUN=1
SECURETEXT_PROFILE_DIR="$profile/p" xvfb-run -a "$app" > "$log" 2>&1 &
pid=$!
sleep 15
if ! kill -0 "$pid" 2>/dev/null; then
    echo "SecureText exited early:"; cat "$log"; exit 1
fi
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
echo "SecureText started and stayed up: $app"
