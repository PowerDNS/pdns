#!/bin/sh
set -v
set -e

[ -e /tmp/.pdns_meson_installed ] && exit 0  # we already have meson, let's assume we put it there earlier

readonly MESON_VERSION=$(jq -r .version < meson.json)
readonly MESON_TARBALL="${MESON_VERSION}.tar.gz"
readonly MESON_TARBALL_URL="https://github.com/mesonbuild/meson/archive/${MESON_TARBALL}"
readonly MESON_TARBALL_HASH=$(jq -r .SHA256SUM < meson.json)

cd /tmp
echo $0: Downloading ${MESON_TARBALL}
curl -L -o "${MESON_TARBALL}" "${MESON_TARBALL_URL}"
echo $0: Checking that the hash of ${MESON_TARBALL} is ${MESON_TARBALL_HASH}
# Line below should echo two spaces between digest and name
echo "${MESON_TARBALL_HASH}""  ""${MESON_TARBALL}" | sha256sum -c -
tar xf "${MESON_TARBALL}"
cd "meson-${MESON_VERSION}"

install -Dpm0644 -t /usr/lib/rpm/macros.d/ data/macros.meson

python3 -m pip install . --break-system-packages || python3 -m pip install .
ln -s /usr/local/bin/meson /usr/bin/meson
PYVERS=$(python3 --version | sed 's/Python //' | cut -d. -f1,2)
if [ -d "/usr/local/lib/python${PYVERS}/dist-packages/mesonbuild" ]; then
    # thanks, Debian and Ubuntu, much appreciated..
    mkdir -p "/usr/lib/python${PYVERS}/dist-packages/mesonbuild"
    ln -s "/usr/local/lib/python${PYVERS}/dist-packages/mesonbuild" "/usr/lib/python${PYVERS}/dist-packages/mesonbuild"
else
    ln -s "/usr/local/lib/python${PYVERS}/site-packages/mesonbuild" "/usr/lib/python${PYVERS}/site-packages/mesonbuild"
fi

cd ..
rm -rf "${MESON_TARBALL}" "meson-${MESON_VERSION}"

touch /tmp/.pdns_meson_installed
