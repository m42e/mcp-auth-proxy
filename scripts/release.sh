#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>"
  echo "  version: semver without leading v (e.g. 1.2.3)"
  exit 1
fi

VERSION="$1"

if ! printf '%s\n' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "Error: version must be in semver format (X.Y.Z)"
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "Error: working directory is not clean"
  exit 1
fi

if git rev-parse -q --verify "refs/tags/v${VERSION}" >/dev/null 2>&1; then
  echo "Error: tag v${VERSION} already exists"
  exit 1
fi

echo "Updating Cargo.toml to version ${VERSION}..."
awk -v ver="$VERSION" '
  /^\[/ { in_pkg = ($0 ~ /^\[package\]([[:space:]]*(#.*)?)?$/) }
  in_pkg && !done && /^version[[:space:]]*=/ {
    $0 = "version = \"" ver "\""
    done = 1
  }
  { print }
  END { if (!done) exit 1 }
' Cargo.toml > Cargo.toml.tmp || { rm -f Cargo.toml.tmp; exit 1; }
mv Cargo.toml.tmp Cargo.toml

echo "Updating Cargo.lock..."
cargo update -w

echo "Creating release commit..."
git add Cargo.toml Cargo.lock
git commit -m "chore: prepare release v${VERSION}"

echo "Creating annotated tag v${VERSION}..."
git tag -a "v${VERSION}" -m "Release v${VERSION}"

echo ""
echo "Release v${VERSION} prepared locally."
echo "Review the commit and tag, then push with:"
echo "  git push origin main v${VERSION}"
