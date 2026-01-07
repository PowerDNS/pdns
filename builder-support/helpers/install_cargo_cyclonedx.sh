#!/bin/sh
set -v
set -e

[ -e /tmp/.pdns_cargocyclonedx_installed ] && exit 0

readonly CARGO_CYCLONEDX_VERSION=$(jq -r .version < cargo_cyclonedx.json)
readonly CARGO_CYCLONEDX_TARBALL="cargo-cyclonedx-${CARGO_CYCLONEDX_VERSION}.tar.gz"
readonly CARGO_CYCLONEDX_TARBALL_URL="https://github.com/CycloneDX/cyclonedx-rust-cargo/archive/refs/tags/${CARGO_CYCLONEDX_TARBALL}"
readonly CARGO_CYCLONEDX_TARBALL_HASH=$(jq -r .SHA256SUM < cargo_cyclonedx.json)

cd /tmp
echo $0: Downloading ${CARGO_CYCLONEDX_TARBALL}
curl -L -o "${CARGO_CYCLONEDX_TARBALL}" "${CARGO_CYCLONEDX_TARBALL_URL}"
echo $0: Checking that the hash of ${CARGO_CYCLONEDX_TARBALL} is ${CARGO_CYCLONEDX_TARBALL_HASH}
# Line below should echo two spaces between digest and name
echo "${CARGO_CYCLONEDX_TARBALL_HASH}""  ""${CARGO_CYCLONEDX_TARBALL}" | sha256sum -c -
tar xf "${CARGO_CYCLONEDX_TARBALL}"
cd "cyclonedx-rust-cargo-cargo-cyclonedx-${CARGO_CYCLONEDX_VERSION}"

# --locked so we use the pinned versions of dependencies
# --path because the tarball contains a library and a binary
# --debug because it is (slightly) faster and we don't care about performance
# --no-track so we do not write a crates.toml file to /
RUST_BACKTRACE=1 cargo install --locked --path cargo-cyclonedx --debug --no-track --root /

cd ..
rm -rf "${CARGO_CYCLONEDX_TARBALL}" "cyclonedx-rust-cargo-cargo-cyclonedx-${CARGO_CYCLONEDX_VERSION}"

touch /tmp/.pdns_cargocyclonedx_installed
