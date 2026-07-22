#!/usr/bin/env bash

# Reproducible dependency bootstrap for native Linux conformance builds.
# This script owns only repository-local build inputs below .tools. It never
# installs system packages, mutates a global OpenSSL provider configuration or
# changes the runtime loader path used by unrelated processes on the runner.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly TOOLS="$ROOT/.tools"
readonly VERSION="3.5.7"
readonly ARCHIVE="$TOOLS/downloads/openssl-$VERSION.tar.gz"
readonly SOURCE="$TOOLS/sources/openssl-$VERSION"
readonly BUILD="$TOOLS/build/native/openssl-$VERSION"
readonly INSTALL="$TOOLS/dependencies/native/openssl-$VERSION"
readonly URL="https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"
readonly EXPECTED_SHA256="a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"

# Both archives are required because CMake requests the SSL and Crypto
# components explicitly. A header-only or half-restored cache entry is not a
# usable installation and must be rebuilt before configuration starts.
has_complete_install() {
  local library_dir
  for library_dir in "$INSTALL/lib64" "$INSTALL/lib"; do
    if [[ -f "$library_dir/libssl.a" && -f "$library_dir/libcrypto.a" &&
          -f "$INSTALL/include/openssl/opensslv.h" ]]; then
      return 0
    fi
  done
  return 1
}

if has_complete_install; then
  printf 'Pinned native OpenSSL %s is already built\n' "$VERSION"
  exit 0
fi

mkdir -p "$(dirname "$ARCHIVE")" "$(dirname "$SOURCE")" \
  "$(dirname "$BUILD")" "$(dirname "$INSTALL")"

if [[ ! -f "$ARCHIVE" ]]; then
  # Retry transient transport failures, but never accept an HTTP error page as
  # an archive. The digest check below remains authoritative after download.
  curl --fail --location --retry 5 --retry-all-errors \
    --output "$ARCHIVE" "$URL"
fi

ACTUAL_SHA256="$(sha256sum "$ARCHIVE" | cut -d ' ' -f 1)"
readonly ACTUAL_SHA256
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
  printf 'OpenSSL archive SHA-256 mismatch: %s\n' "$ACTUAL_SHA256" >&2
  exit 1
fi

# Every removable path is a fixed descendant of the repository-local .tools
# directory. The guard prevents a future variable edit from widening cleanup
# to the workspace root or runner filesystem.
for path in "$SOURCE" "$BUILD" "$INSTALL"; do
  case "$path" in
    "$TOOLS"/*) ;;
    *) printf 'Refusing unsafe cleanup path: %s\n' "$path" >&2; exit 1 ;;
  esac
done
rm -rf -- "$SOURCE" "$BUILD" "$INSTALL"

tar -xzf "$ARCHIVE" -C "$(dirname "$SOURCE")"
mkdir -p "$BUILD" "$INSTALL"

pushd "$BUILD" >/dev/null
# Native sanitizer jobs validate the same OpenSSL release line used by the
# Wasm runtime. Static libraries prevent a runner-provided 3.0 shared object
# from being selected later by the loader despite a successful CMake lookup.
"$SOURCE/Configure" linux-x86_64 no-shared no-module no-tests no-apps \
  "--prefix=$INSTALL" "--openssldir=$INSTALL/ssl"
make -j"$(nproc)" build_sw
make install_sw
popd >/dev/null

if ! has_complete_install; then
  printf 'OpenSSL installation is incomplete after a successful build\n' >&2
  exit 1
fi

printf 'OpenSSL %s native dependency built and verified\n' "$VERSION"
