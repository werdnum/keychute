#!/bin/bash
# SessionStart hook: install a pinned, prebuilt gh-stack binary as a gh CLI
# extension so the gh-stack skill works in Claude Code on the web sessions.
#
# `gh extension install github/gh-stack` does not work there: it looks up the
# release through api.github.com, which the session proxy only serves for the
# repositories attached to the session. The release download URL on github.com
# is reachable, so fetch the asset directly and check it against a pinned hash.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

VERSION="0.2.1"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    ASSET="linux-amd64"
    SHA256="ffe9d48b6342faffc3b0cb420202ff1df32e24faf32693debd7423274bbdf859"
    ;;
  Linux-aarch64 | Linux-arm64)
    ASSET="linux-arm64"
    SHA256="25ec261a391261a1462d38f85c230b0e0b14ae3547926130996541f62f25f78b"
    ;;
  *)
    echo "gh-stack: no pinned binary for $(uname -s)-$(uname -m); skipping" >&2
    exit 0
    ;;
esac

EXT_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/gh/extensions/gh-stack"
BIN="$EXT_DIR/gh-stack"

if [ -x "$BIN" ] && echo "$SHA256  $BIN" | sha256sum --check --status; then
  exit 0
fi

mkdir -p "$EXT_DIR"
TMP="$(mktemp "$EXT_DIR/.gh-stack.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
curl -fsSL --retry 3 -o "$TMP" \
  "https://github.com/github/gh-stack/releases/download/v${VERSION}/${ASSET}"
if ! echo "$SHA256  $TMP" | sha256sum --check --status; then
  echo "gh-stack: checksum mismatch for v${VERSION} ${ASSET}; not installing" >&2
  exit 1
fi
chmod +x "$TMP"
mv "$TMP" "$BIN"
echo "gh-stack v${VERSION} installed" >&2
