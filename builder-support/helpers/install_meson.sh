#!/bin/sh
set -v
set -e

readonly MESON_VERSION=$(jq -r .version < meson.json)
readonly MESON_TARBALL="${MESON_VERSION}.tar.gz"
readonly MESON_TARBALL_URL="https://github.com/mesonbuild/meson/archive/${MESON_TARBALL}"
readonly MESON_TARBALL_HASH=$(jq -r .SHA256SUM < meson.json)

cd /tmp
echo $0: Downloading ${MESON_TARBALL}
curl -L -o "${MESON_TARBALL}" "${MESON_TARBALL_URL}"
echo $0: Checking that the hash of ${MESON_TARBALL} is ${MESON_TARBALL_HASH}
# Line below should echo two spaces between digest and name
echo "${MESON_TARBALL_HASH}"  "${MESON_TARBALL}" | sha256sum -c -
tar xf "${MESON_TARBALL}"
cd "meson-${MESON_VERSION}"

python setup.py build
python setup.py install

cd ..
rm -rf "${MESON_TARBALL}" "meson-${MESON_VERSION}"
