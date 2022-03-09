#!/bin/bash
#
# This script installs native cross compilation tools and bundlers them into a /native.tar
# that is meant to be unpacked to the root of the builder stage.
# The tarball includes various binaries, including /bin/*, to speed up build scripts.
# If the native architecture is the same as the target architecture, or the architecture
# is not explicitly supported by this script, the generated tarball will be empty.
#
# The env vars TARGETPLATFORM and BUILDPLATFORM must be set.
#

set -e

echo "* TARGETPLATFORM: $TARGETPLATFORM"
echo "* BUILDPLATFORM:  $BUILDPLATFORM"

if [ -z "$TARGETPLATFORM" ] || [ -z "$BUILDPLATFORM" ] ; then
    echo "Both TARGETPLATFORM and BUILDPLATFORM must be set!" > /dev/stderr
    exit 10
fi

tarfile=/native.tar

function no_native_tools {
    # We need to generate some tar file
    touch /buildenv.sh
    tar -cf "$tarfile" /buildenv.sh
    echo "WARNING: No native tools were bundled." > /dev/stderr
    exit 0
}

if [ "$TARGETPLATFORM" = "$BUILDPLATFORM" ]; then
    echo "The target platform is the same as the build platform, nothing to do."
    no_native_tools
fi

if [ "$NO_NATIVE" = "1" ]; then
    echo "Buildarg NO_NATIVE=1, skipping native tool bundling."
    no_native_tools
fi

# The busybox image supports many architectures, you can check for architecture names
# there: https://hub.docker.com/_/busybox?tab=tags
# For debian architecture names, I used `apt search crossbuild`.
# WARNING: Not all of these will actually work in QEMU, which is no worse than without these tools.
case "$TARGETPLATFORM" in
linux/amd64)
    debianarch=amd64
    ;;
linux/386)
    debianarch=i386
    ;;
linux/arm64)
    debianarch=arm64
    ;;
linux/arm64/v8)
    debianarch=arm64
    ;;
linux/arm/v7)
    debianarch=armhf
    ;;
linux/arm/v6)
    debianarch=armel
    ;;
linux/arm/v5)
    # TODO: unsure about this one, supported?
    debianarch=armel
    ;;
linux/ppc64le)
    debianarch=ppc64el
    ;;
linux/riscv64)
    debianarch=riscv64
    ;;
linux/s390x)
    debianarch=s390x
    ;;
*)
    # When adding new ones, map the Docker name to the GNU name.
    # We currently also assume that the Debian name is the same as the Docker name.
    echo "WARNING: TARGETPLATFORM $TARGETPLATFORM not supported yet. Please check builder-support/cross/*.sh" > /dev/stderr
    no_native_tools
    ;;
esac

set -x

apt-get install -y --no-install-recommends \
    crossbuild-essential-$debianarch \
    libatomic1-$debianarch-cross \
    m4 make dpkg-dev

apt-get clean

dpkg-architecture --host-arch $debianarch > /buildenv.sh

# Also copy faster native version of some tools
tar -cf "$tarfile" \
    /usr/bin/*-linux-gnu* \
    /usr/*-linux-gnu* \
    /lib/*-linux-gnu* \
    /usr/lib/*-linux-gnu* \
    /usr/lib/gcc* \
    /lib*/ld-linux-* \
    /usr/bin/m4 \
    /usr/bin/make \
    /bin \
    /buildenv.sh

echo "$tarfile generated."

