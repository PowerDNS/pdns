#!/bin/sh -e

echo Running meson-dist-script
echo PWD=$(pwd)
echo MESON_SOURCE_ROOT=$MESON_SOURCE_ROOT
echo MESON_PROJECT_DIST_ROOT=$MESON_PROJECT_DIST_ROOT

if [ -z "${BUILDER_VERSION}" ]; then
    echo "BUILDER_VERSION is not set" >&2
    exit 1
fi

cd "$MESON_PROJECT_DIST_ROOT"

# Get all symlinks
symlinks=$(find . -type l)

# If these two get out-of-sync, fix it! It used to be a symlink but that can no longer be as we are
# working with a partial checkout in the dist root dir.
cmp "$MESON_SOURCE_ROOT"/../../builder-support/gen-version "$MESON_PROJECT_DIST_ROOT"/builder-support/gen-version

# Get the dereffed symbolic links (the actual files being pointed to) from the source dir
# Extract them over the existing symbolic links
tar -C "$MESON_SOURCE_ROOT" -hcf - $symlinks | tar -xf - -C "$MESON_PROJECT_DIST_ROOT"

# set the proper version in configure.ac
"$MESON_SOURCE_ROOT"/../../builder/helpers/set-configure-ac-version.sh
# Run autoconf for people using autotools to build, this creates a configure script with VERSION set
echo Running autoreconf -vi so distfile is still usable for autotools building
# Run autoconf for people using autotools to build, this creates a configure sc
autoreconf -vi
rm -rf "$MESON_PROJECT_DIST_ROOT"/autom4te.cache
echo Updating the version of the Rust library to ${BUILDER_VERSION}
"$MESON_SOURCE_ROOT"/../../builder-support/helpers/update-rust-library-version.py "$MESON_PROJECT_DIST_ROOT"/dnsdist-rust-lib/rust/Cargo.toml dnsdist-rust ${BUILDER_VERSION}

cd "$MESON_PROJECT_BUILD_ROOT"

# Generate YAML documentation
meson compile yaml-settings-docs
cp -vp "$MESON_SOURCE_ROOT"/docs/reference/yaml-*.rst "$MESON_PROJECT_DIST_ROOT"/docs/reference/

# Generate a few files to reduce build dependencies
echo 'If the below command generates an error, remove dnslabeltext.cc from source dir (remains of an autotools build?) and start again with a clean meson setup'
ninja libdnsdist-common.a.p/dnslabeltext.cc
cp -vp libdnsdist-common.a.p/dnslabeltext.cc "$MESON_PROJECT_DIST_ROOT"

# Generate rules (selectors, actions)
meson compile rules
cp -vp dnsdist-*generated.hh dnsdist-*generated-body.hh "$MESON_PROJECT_DIST_ROOT"

# Generate the sources for our Rust-based library
meson compile rust-lib-sources
cp -vp dnsdist-rust-lib/*.cc dnsdist-rust-lib/*.hh "$MESON_PROJECT_DIST_ROOT"/dnsdist-rust-lib/
cp -vp "$MESON_SOURCE_ROOT"/dnsdist-rust-lib/rust/src/lib.rs "$MESON_PROJECT_DIST_ROOT"/dnsdist-rust-lib/rust/src/

echo Updating the version of the Rust library to ${BUILDER_VERSION}
"$MESON_SOURCE_ROOT"/../../builder-support/helpers/update-rust-library-version.py "$MESON_PROJECT_DIST_ROOT"/dnsdist-rust-lib/rust/Cargo.toml dnsdist-rust ${BUILDER_VERSION}
# Update the version of the Rust library in Cargo.lock as well,
# This needs to be done AFTER the sources of the Rust library have been generated
# Unfortunately we cannot use --offline because for some reason cargo-update wants
# to check all dependencies even though we are telling it exactly what to update
cd "$MESON_PROJECT_DIST_ROOT"/dnsdist-rust-lib/rust/
cargo update --verbose --precise ${BUILDER_VERSION} dnsdist-rust
cd "$MESON_PROJECT_BUILD_ROOT"

# Generate man pages
meson compile man-pages
cp -vp *.1 "$MESON_PROJECT_DIST_ROOT"
