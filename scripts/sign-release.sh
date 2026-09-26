#!/usr/bin/env bash
# Publish a draft release made by the release pipeline (docs/releasing.md).
#
#   scripts/sign-release.sh v0.2.0 /path/to/update-signing.key RELEASE-NOTES.md
#
# 1. Downloads the draft's installers and checks them against SHA256SUMS.
# 2. Builds securetext-update.json (the signed update manifest) on THIS
#    machine with the offline update-signing key, and verifies it against
#    the public key pinned in desktop/update-signing.pub.
# 3. Uploads the manifest and publishes the release. Installed copies of
#    SecureText find it (over Tor) at releases/latest/download/.
#
# Needs: gh (logged in), a Rust toolchain. The key's passphrase is asked
# for on standard input (or taken from SECURETEXT_RELEASE_PASSPHRASE).
set -euo pipefail
tag="${1:?usage: sign-release.sh vX.Y.Z <signing-key-file> <notes-file>}"
key="${2:?signing key file}"
notes="${3:?release notes file}"
repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
version="${tag#v}"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Downloading draft $tag from $repo..."
gh release download "$tag" --repo "$repo" --dir "$work"
(cd "$work" && sha256sum --check SHA256SUMS)

one() { # exactly one file matching the pattern
    local matches=("$work"/$1)
    [ "${#matches[@]}" -eq 1 ] && [ -e "${matches[0]}" ] || { echo "expected one $1 in the release" >&2; exit 1; }
    echo "${matches[0]}"
}
assets=(
    --asset "linux-x86_64-appimage=$(one "SecureText_${version}_amd64.AppImage")"
    --asset "linux-x86_64-deb=$(one "SecureText_${version}_amd64.deb")"
    --asset "linux-x86_64-rpm=$(one "SecureText-${version}-1.x86_64.rpm")"
    --asset "windows-x86_64-nsis=$(one "SecureText_${version}_x64-setup.exe")"
    --asset "windows-x86_64-msi=$(one "SecureText_${version}_x64_en-US.msi")"
)

cargo run --quiet --release --manifest-path "$root/Cargo.toml" -p securetext-update --bin securetext-release -- \
    manifest --version "$version" --notes-file "$notes" \
    --base-url "https://github.com/$repo/releases/download/$tag" \
    "${assets[@]}" --key-file "$key" --out "$work/securetext-update.json"
cargo run --quiet --release --manifest-path "$root/Cargo.toml" -p securetext-update --bin securetext-release -- \
    verify "$work/securetext-update.json" "$root/desktop/update-signing.pub"

gh release upload "$tag" "$work/securetext-update.json" --repo "$repo" --clobber
gh release edit "$tag" --repo "$repo" --notes-file "$notes" --draft=false --latest
echo "Published $tag. Installed copies will see it within about a day."
