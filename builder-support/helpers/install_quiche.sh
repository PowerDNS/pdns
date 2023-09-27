#!/bin/sh
set -v
set -e

readonly QUICHE_VERSION='0.18.0'
readonly QUICHE_TARBALL="${QUICHE_VERSION}.tar.gz"
readonly QUICHE_TARBALL_URL="https://github.com/cloudflare/quiche/archive/${QUICHE_TARBALL}"
readonly QUICHE_TARBALL_HASH='eb242a14c4d801a90b57b6021dd29f7a62099f3a4d7a7ba889e105f8328e6c1f'

cd /tmp
echo $0: Downloading $QUICHE_TARBALL
curl -L -o "${QUICHE_TARBALL}" "${QUICHE_TARBALL_URL}"
# Line below should echo two spaces between digest and name
echo "${QUICHE_TARBALL_HASH}"  "${QUICHE_TARBALL}" | sha256sum -c -
tar xf "${QUICHE_TARBALL}"
cd "quiche-${QUICHE_VERSION}"
RUST_BACKTRACE=1 cargo build --release --no-default-features --features ffi,boringssl-boring-crate --package quiche
install -Dm644 quiche/include/quiche.h /usr/include
install -Dm644 target/release/libquiche.so /usr/lib/libdnsdist-quiche.so
install -Dm644 /dev/stdin /usr/lib/pkgconfig/quiche.pc <<PC
# quiche
Name: quiche
Description: quiche library
URL: https://github.com/cloudflare/quiche
Version: ${QUICHE_VERSION}
Libs: -ldnsdist-quiche
PC

cd ..
rm -rf "${QUICHE_TARBALL}" "quiche-${QUICHE_VERSION}"
