#!/bin/sh -e

echo Running meson-dist-script
echo PWD=$(pwd)
echo MESON_SOURCE_ROOT=$MESON_SOURCE_ROOT
echo MESON_PROJECT_DIST_ROOT=$MESON_PROJECT_DIST_ROOT

cd "$MESON_PROJECT_DIST_ROOT"

# Get all symlinks
symlinks=$(find . -type l)

# Get the dereffed symbolic links (the actual files being pointed to) from the source dir
# Extract them over the existing symbolic links
tar -C "$MESON_SOURCE_ROOT" -hcf - $symlinks | tar -xf - -C "$MESON_PROJECT_DIST_ROOT"

# Run autoconf for people using autotools to build, this creates a configure script with VERSION set
echo Running autoreconf -vi so distfile is still usable for autotools building
# Run autoconf for people using autotools to build, this creates a configure sc
autoreconf -vi

# Generate man pages
cd "$MESON_PROJECT_BUILD_ROOT"
ninja man-pages
cp -vp rec-man-pages/*.1 "$MESON_PROJECT_DIST_ROOT"
ninja  librec-dnslabeltext.a.p/dnslabeltext.cc
cp -vp librec-dnslabeltext.a.p/dnslabeltext.cc "$MESON_PROJECT_DIST_ROOT"

