#!/bin/sh

set -e

[ -e /tmp/.pdns_rust_installed ] && exit 0

ARCH=$(arch)

# Default version
RUST_VERSION_NUMBER=$(jq -r .version < rust.json)
RUST_VERSION=rust-$RUST_VERSION_NUMBER-$ARCH-unknown-linux-gnu

if [ $# -ge 1 ]; then
    RUST_VERSION=$1
    shift
fi

SITE=https://downloads.powerdns.com/rust
RUST_TARBALL=$RUST_VERSION.tar.xz

SHA256SUM_x86_64=$(jq -r .SHA256SUM_x86_64 < rust.json)
SHA256SUM_aarch64=$(jq -r .SHA256SUM_aarch64 < rust.json)

NAME=SHA256SUM_$ARCH
eval VALUE=\$$NAME
if [ -z "$VALUE" ]; then
    echo "$0: No SHA256 defined for $ARCH" > /dev/stderr
    exit 1
fi

# Procedure to update the Rust tarball:
# 1. Download tarball and signature (.asc) file from
#    https://forge.rust-lang.org/infra/other-installation-methods.html "Standalone installers" section
# 2. Import Rust signing key into your gpg if not already done so
# 3. Run gpg --verify $RUST_TARBALL.asc and make sure it is OK
# 4. Run sha256sum $RUST_TARBALL and set SHA256SUM above, don't forget to update RUST_VERSION as well
# 5. Make $RUST_TARBALL available from https://downloads.powerdns.com/rust
#
cd /tmp
if [ -f $RUST_TARBALL ]; then
    echo $0: Found existing $RUST_TARBALL
else
    echo $0: Downloading $RUST_TARBALL
    rm -f $RUST_TARBALL
    curl --silent --show-error --fail --output $RUST_TARBALL $SITE/$RUST_TARBALL
fi
echo $0: Expecting hash $VALUE
# Line below should echo two spaces between digest and name
if echo "${VALUE}  ${RUST_TARBALL}" | sha256sum -c -; then
  true
else
  result=$?
  echo "error: Downloaded ${SITE}/${RUST_TARBALL} failed sha256sum validation"
  exit $result
fi
rm -rf $RUST_VERSION
tar -Jxf $RUST_TARBALL
cd $RUST_VERSION
./install.sh --prefix=/usr --components=rustc,rust-std-$ARCH-unknown-linux-gnu,cargo

cd ..
rm -rf $RUST_VERSION

touch /tmp/.pdns_rust_installed
