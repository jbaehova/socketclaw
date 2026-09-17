#!/bin/sh
set -eu

case "$(uname -s)" in
  Darwin) ;;
  *) echo "SocketClaw standalone releases currently support macOS only." >&2; exit 1 ;;
esac

case "$(uname -m)" in
  arm64) architecture=arm64 ;;
  x86_64) architecture=x86_64 ;;
  *) echo "Unsupported Mac architecture: $(uname -m)" >&2; exit 1 ;;
esac

release="${SOCKETCLAW_VERSION:-latest}"
case "$release" in
  latest) release_path=latest/download ;;
  v[0-9]*) release_path="download/$release" ;;
  *) echo "SOCKETCLAW_VERSION must be latest or a version tag such as v0.3.0." >&2; exit 1 ;;
esac

asset="socketclaw-darwin-$architecture.tar.gz"
base="https://github.com/jbaehova/SocketClaw/releases/$release_path"
install_dir="${SOCKETCLAW_INSTALL_DIR:-$HOME/.local/bin}"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

curl --fail --location --silent --show-error "$base/$asset" -o "$temporary/$asset"
curl --fail --location --silent --show-error "$base/SHA256SUMS" -o "$temporary/SHA256SUMS"

expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$temporary/SHA256SUMS")
if [ -z "$expected" ]; then
  echo "No checksum found for $asset." >&2
  exit 1
fi
actual=$(shasum -a 256 "$temporary/$asset" | awk '{ print $1 }')
if [ "$actual" != "$expected" ]; then
  echo "Checksum verification failed for $asset." >&2
  exit 1
fi

tar -xzf "$temporary/$asset" -C "$temporary" socketclaw
mkdir -p "$install_dir"
install -m 755 "$temporary/socketclaw" "$install_dir/socketclaw.new.$$"
mv -f "$install_dir/socketclaw.new.$$" "$install_dir/socketclaw"
echo "Installed SocketClaw to $install_dir/socketclaw"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "Add $install_dir to PATH, then run: socketclaw" ;;
esac
