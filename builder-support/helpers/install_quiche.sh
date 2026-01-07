#!/bin/sh
set -v
set -e

[ -e /tmp/.pdns_quiche_installed ] && exit 0

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
LIBDIR="${INSTALL_PREFIX}/lib"

if [ $(uname) != Darwin ]; then
  for tentative in "${INSTALL_PREFIX}/lib/x86_64-linux-gnu" "${INSTALL_PREFIX}/lib/aarch64-linux-gnu" "${INSTALL_PREFIX}/lib64" "${INSTALL_PREFIX}/lib"; do
    if [ -f "${tentative}/libc.so" ]; then
      LIBDIR="${tentative}"
      break
    fi
  done
fi
echo "LIBDIR is ${LIBDIR}"

cd /tmp
echo $0: Downloading ${QUICHE_TARBALL}
curl -L -o "${QUICHE_TARBALL}" "${QUICHE_TARBALL_URL}"
echo $0: Checking that the hash of ${QUICHE_TARBALL} is ${QUICHE_TARBALL_HASH}
# Line below should echo two spaces between digest and name
echo "${QUICHE_TARBALL_HASH}""  ""${QUICHE_TARBALL}" | sha256sum -c -
tar xf "${QUICHE_TARBALL}"
cd "quiche-${QUICHE_VERSION}"
# Disable SONAME in the quiche shared library, we do not intend this library to be used by anyone else and it makes things more complicated since we rename it to libdnsdist-quiche
sed -i.bak 's/ffi = \["dep:cdylib-link-lines"\]/ffi = \[\]/' quiche/Cargo.toml
sed -i.bak 's,cdylib_link_lines::metabuild();,//cdylib_link_lines::metabuild();,' quiche/src/build.rs
RUST_BACKTRACE=1 cargo build --release --no-default-features --features ffi,boringssl-boring-crate --package quiche

# While we tried to get rid of the SONAME in libquiche.so, on debian trixie's
# packaged rustc puts it in anyway.
# See (https://sources.debian.org/patches/rustc/1.85.0%2Bdfsg2-3/behaviour/d-rustc-add-soname.patch/).
# So if it is present, patch it to the correct name.
if objdump -p target/release/libquiche.${SOEXT} | grep -F -q SONAME
then
  patchelf --set-soname libdnsdist-quiche.so target/release/libquiche.${SOEXT}
fi

install -m644 quiche/include/quiche.h "${INSTALL_PREFIX}"/include
install -m644 target/release/libquiche.${SOEXT} "${LIBDIR}"/libdnsdist-quiche.${SOEXT}

if [ $(uname) = Darwin ]; then
  install_name_tool -id "${LIBDIR}/libdnsdist-quiche.${SOEXT}" "${LIBDIR}"/libdnsdist-quiche.${SOEXT}
fi

if [ ! -d "${LIBDIR}"/pkgconfig/ ]; then
    mkdir "${LIBDIR}"/pkgconfig/
fi
install -m644 /dev/stdin "${LIBDIR}"/pkgconfig/quiche.pc <<PC
# quiche
Name: quiche
Description: quiche library
URL: https://github.com/cloudflare/quiche
Version: ${QUICHE_VERSION}
Cflags: -I${INSTALL_PREFIX}/include
Libs: -L${LIBDIR} -ldnsdist-quiche
PC

if [ -f /bin/cargo-cyclonedx ]; then
    /bin/cargo-cyclonedx cyclonedx -f json --spec-version 1.5
    mv quiche/quiche.cdx.json /dist/
fi

cd ..
rm -rf "${QUICHE_TARBALL}" "quiche-${QUICHE_VERSION}"

touch /tmp/.pdns_quiche_installed
