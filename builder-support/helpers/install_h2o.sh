#!/bin/sh
set -v
set -e

readonly H2O_VERSION=$(jq -r .version < h2o.json)
readonly H2O_TARBALL="v${H2O_VERSION}.tar.gz"
readonly H2O_TARBALL_URL="https://github.com/PowerDNS/h2o/archive/refs/tags/${H2O_TARBALL}"
readonly H2O_TARBALL_HASH=$(jq -r .SHA256SUM < h2o.json)

cd /tmp
echo $0: Downloading $H2O_TARBALL
curl -f -L -o "${H2O_TARBALL}" "${H2O_TARBALL_URL}"

# Line below should echo two spaces between digest and name
if echo "${H2O_TARBALL_HASH}  ${H2O_TARBALL}" | sha256sum -c -; then
  true
else
  result=$?
  echo "error: Downloaded ${H2O_TARBALL_URL} failed sha256sum validation"
  exit $result
fi
tar xf "${H2O_TARBALL}"
CFLAGS='-fPIC' cmake -DWITH_PICOTLS=off -DWITH_BUNDLED_SSL=off -DWITH_MRUBY=off -DCMAKE_INSTALL_PREFIX=/opt ./h2o-${H2O_VERSION}
make -j $(nproc)
make install
rm -rf "${H2O_TARBALL}" "h2o-${H2O_VERSION}"
