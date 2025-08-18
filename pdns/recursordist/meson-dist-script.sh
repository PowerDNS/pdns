#!/bin/sh -e

echo Running meson-dist-script
echo PWD=$(pwd)
echo MESON_SOURCE_ROOT=$MESON_SOURCE_ROOT
echo MESON_PROJECT_DIST_ROOT=$MESON_PROJECT_DIST_ROOT

cd "$MESON_PROJECT_DIST_ROOT"

# Get all symlinks
symlinks=$(find . -type l)

# If these two get out-of-sync, fix it! It used to be a symlink but that can no longer be as we are
# working with a partial checkout in the dist root dir.
cmp "$MESON_SOURCE_ROOT"/../../builder-support/gen-version "$MESON_PROJECT_DIST_ROOT"/builder-support/gen-version

# Get the dereffed symbolic links (the actual files being pointed to) from the source dir
# Extract them over the existing symbolic links
tar -C "$MESON_SOURCE_ROOT" -hcf - $symlinks | tar -xf - -C "$MESON_PROJECT_DIST_ROOT"

# Run autoconf for people using autotools to build, this creates a configure script with VERSION set
echo Running autoreconf -vi so distfile is still usable for autotools building
# Run autoconf for people using autotools to build, this creates a configure sc
autoreconf -vi
rm -rf "$MESON_PROJECT_DIST_ROOT"/autom4te.cache

cd "$MESON_PROJECT_BUILD_ROOT"

# Generate  a few files to reduce build dependencies
echo 'If the below command generates an error, remove dnslabeltext.cc from source dir (remains of an autotools build?) and start again with a clean meson setup'
ninja librec-dnslabeltext.a.p/dnslabeltext.cc
cp -vp librec-dnslabeltext.a.p/dnslabeltext.cc "$MESON_PROJECT_DIST_ROOT"
echo 'If the below command generates an error, remove effective_tld_names.dat and pubsuffix.cc from source dir (remains of an autotools build?) and start again with a clean meson setup'
ninja pubsuffix.cc
cp -vp pubsuffix.cc "$MESON_PROJECT_DIST_ROOT"

# Generate the sources for our Rust-based library, lib.rs is needed by a pre-configure step on some build systems
meson compile rec-rust-sources
cp -vp "$MESON_SOURCE_ROOT"/rec-rust-lib/rust/src/lib.rs "$MESON_PROJECT_DIST_ROOT"/rec-rust-lib/rust/src/

# Generate man pages
meson compile man-pages
cp -vp *.1 "$MESON_PROJECT_DIST_ROOT"
