#!/usr/bin/env bash
# build-image — reproducibility gate for the sandbox image (design.md §5.4:
# "镜像两次构建同 digest"). Builds the image twice and compares digests.
#
#   sandbox/scripts/build-image.sh            build + verify digest stability
#   sandbox/scripts/build-image.sh --build-only
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-pi4ctf-sandbox:latest}"
BUILD_ONLY="${1:-}"

# Reproducibility gate 0: refuse to build with unpinned base/ghidra (review R6).
if grep -q 'REPLACE_WITH_PINNED_DIGEST\|REPLACE_WITH_GHIDRA_ZIP_SHA256' Dockerfile.kali; then
  echo "FAIL: Dockerfile.kali still has placeholder digests." >&2
  echo "  1. docker manifest inspect kalilinux/kali-rolling:latest -> KALI_BASE" >&2
  echo "  2. sha256sum ghidra_*.zip -> GHIDRA_SHA256" >&2
  exit 1
fi

docker build -f Dockerfile.kali -t "$IMAGE" .

if [ "$BUILD_ONLY" = "--build-only" ]; then
  docker image inspect "$IMAGE" --format '{{.Id}}'
  exit 0
fi

FIRST=$(docker image inspect "$IMAGE" --format '{{.Id}}')
echo "first digest:  $FIRST"

# Rebuild from scratch and compare.
docker build --no-cache -f Dockerfile.kali -t "$IMAGE" . >/dev/null
SECOND=$(docker image inspect "$IMAGE" --format '{{.Id}}')
echo "second digest: $SECOND"

if [ "$FIRST" != "$SECOND" ]; then
  echo "FAIL: digests differ — image build is not reproducible" >&2
  exit 1
fi
echo "OK: reproducible build, digest pinned"

# Export the zero-LLM toolbox digest for the adapter to copy into .ctf/.
docker run --rm --entrypoint /bin/sh "$IMAGE" -c 'cat /opt/toolbox.digest.json' > toolbox.digest.json
echo "toolbox digest written to sandbox/toolbox.digest.json ($(wc -c < toolbox.digest.json) bytes)"
