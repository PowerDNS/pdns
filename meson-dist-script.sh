#!/bin/sh -e

echo Running meson-dist-script
echo PWD=$(pwd)
echo MESON_SOURCE_ROOT=$MESON_SOURCE_ROOT
echo MESON_PROJECT_DIST_ROOT=$MESON_PROJECT_DIST_ROOT

if [ -z "${MESON_PROJECT_DIST_ROOT}" ]; then
    echo "MESON_PROJECT_DIST_ROOT is not set" >&2
    exit 1
fi

cd "$MESON_PROJECT_DIST_ROOT"

rm AI_POLICY.md BUILDING-PACKAGES.md CODE_COVERAGE.md
rm Brewfile
rm -r builder
rm -r builder-support
rm -r build-scripts
rm -r contrib
rm docker-compose.yml
rm -r dockerdata
rm Dockerfile*
rm .dockerignore
rm -r ext/ipcrypt2
rm -r ext/libbpf
rm -r ext/probds
rm -r fuzzing
rm invoke.yaml
rm lgtm.yml
rm Makefile.docker
rm -r pdns/dnsdistdist
rm -r pdns/recursordist
rm -r regression-tests.dnsdist
rm -r regression-tests.recursor
rm -r regression-tests.recursor-dnssec
rm tasks.py
rm -r website

# TODO: Generate man pages
# TODO: openapi
