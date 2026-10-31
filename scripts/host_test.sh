#!/usr/bin/env bash
# Builds and runs the host test suite in a clean Linux container.
#   scripts/host_test.sh            normal build
#   scripts/host_test.sh --asan     with AddressSanitizer + UBSan
set -euo pipefail
cd "$(dirname "$0")/.."

SAN=OFF
BUILD=/build/host
if [[ "${1:-}" == "--asan" ]]; then SAN=ON; BUILD=/build/host-asan; fi

SRC="$(pwd)"
if command -v cygpath >/dev/null 2>&1; then SRC="$(cygpath -w "$SRC")"; fi
export MSYS_NO_PATHCONV=1

docker build -q -t lintel-host -f test/host/Dockerfile test/host >/dev/null
docker run --rm -v "$SRC":/src:ro -v lintel-host-build:/build -w /src lintel-host bash -c "
  cmake -S test/host -B $BUILD -G Ninja -DCMAKE_BUILD_TYPE=Debug -DLINTEL_SANITIZE=$SAN >/dev/null &&
  cmake --build $BUILD &&
  ctest --test-dir $BUILD --output-on-failure"
