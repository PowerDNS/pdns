#!/bin/sh
set -v
set -e

readonly QUICHE_VERSION=$(jq -r .version < quiche.json)
readonly QUICHE_TARBALL="${QUICHE_VERSION}.tar.gz"
readonly QUICHE_TARBALL_URL="https://github.com/cloudflare/quiche/archive/${QUICHE_TARBALL}"
readonly QUICHE_TARBALL_HASH=$(jq -r .SHA256SUM < quiche.json)

INSTALL_PREFIX=/usr
SOEXT=so
if [ $(uname) = Darwin ]; then
  if [ $(id -u) = 0 ]; then
    echo Do not run as root on macOS
    exit 1
  fi
  INSTALL_PREFIX="${HOMEBREW_PREFIX}"
  SOEXT=dylib
fi

cd /tmp
echo $0: Downloading ${QUICHE_TARBALL}
curl -L -o "${QUICHE_TARBALL}" "${QUICHE_TARBALL_URL}"
echo $0: Checking that the hash of ${QUICHE_TARBALL} is ${QUICHE_TARBALL_HASH}
# Line below should echo two spaces between digest and name
echo "${QUICHE_TARBALL_HASH}"  "${QUICHE_TARBALL}" | sha256sum -c -
tar xf "${QUICHE_TARBALL}"
cd "quiche-${QUICHE_VERSION}"
RUST_BACKTRACE=1 cargo build --release --no-default-features --features ffi,boringssl-boring-crate --package quiche

install -m644 quiche/include/quiche.h "${INSTALL_PREFIX}"/include
install -m644 target/release/libquiche.${SOEXT} "${INSTALL_PREFIX}"/lib/libdnsdist-quiche.${SOEXT}

if [ $(uname) = Darwin ]; then
  install_name_tool -id "${INSTALL_PREFIX}"/lib/libdnsdist-quiche.${SOEXT} "${INSTALL_PREFIX}"/lib/libdnsdist-quiche.${SOEXT}
fi

if [ ! -d "${INSTALL_PREFIX}"/lib/pkgconfig/ ]; then
    mkdir "${INSTALL_PREFIX}"/lib/pkgconfig/
fi
install -m644 /dev/stdin "${INSTALL_PREFIX}"/lib/pkgconfig/quiche.pc <<PC
# quiche
Name: quiche
Description: quiche library
URL: https://github.com/cloudflare/quiche
Version: ${QUICHE_VERSION}
Cflags: -I${INSTALL_PREFIX}/include
Libs: -L${INSTALL_PREFIX}/lib -ldnsdist-quiche
PC

cd ..
rm -rf "${QUICHE_TARBALL}" "quiche-${QUICHE_VERSION}"
