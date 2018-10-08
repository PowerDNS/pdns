Build Script for PowerDNS
-------------------------
The scripts in this directory are used by the folks at PowerDNS to build
packages. This README will give a small walkthrough of important files.

All `build-*` must be run from the root folder of the pdns repository to ensure
their correct functionality.

## How do I build a package

Before a package can be built, the distribution tarball has to exist in the root
directory. For auth:

 * `autoreconf -i`
 * `./configure --without-modules --without-dynmodules --disable-depedency-tracking`
 * `make dist`

For the recursor:

 * `cd pdns/recursordist`
 * `autoreconf -i`
 * `./configure --disable-dependency-tracking`
 * `make dist`
 * `mv pdns-recursor*.tar.bz2 ../../`
 * `cd -`

And dnsdist:

 * `cd pdns/dnsdistdist`
 * `autoreconf -i`
 * `./configure --disable-dependency-tracking`
 * `make dist`
 * `mv dnsdist*.tar.bz2 ../../`
 * `cd -`

Now two environment variables need to be set, `$VERSION` and `$RELEASE`.

`$VERSION` must be set to the to the version in the tarball to build a package for.
If the version of the package has to be different (e.g. '4.1.0~beta1'), set
`$VERSION` to *that* number and set `$TARBALLVERSION` to the tarball's version.

`$RELEASE` is the 'release' version number for the package (e.g. '1.pdns' or
'0.beta1').

So, to create a package for 0.0.1 for debian version '0.0.1-1pdns0':

 * VERSION=0.0.1
 * RELEASE=1pdns0

0.0.1-beta2 for EL7 (0.0.1-0.beta.2.pdns):

 * VERSION=0.0.1
 * TARBALLVERSION=0.0.1-beta2
 * RELEASE=0.beta.2.pdns

0.0.1-rc1 for debian (0.0.1~rc1-1pdns0):

 * VERSION=0.0.1~rc1
 * TARBALLVERSION=0.0.1-rc1
 * RELEASE=1pdns0

And run the proper script:

## `build-auth-*`
These scripts build (based on the suffix) a package of the authoritative
server. Either RPM's (for several different RHEL-based distro's), .deb's.

## `build-recursor-*`
Based on suffix, these scripts build a deb/RPM package for the Recursor. There is
also a semi-static build script.

## `build-dnsdist-*`
Idem, these scripts allow one to build packages from a dnsdist distribution
directory.

## `debian-*`
These directories contain the `debian/` directory used by the debhelper programs
to create the packages. These are copied by the `build-*` scripts when needed.

# Caveat
These scripts are more or less private - feel free to edit them, but even
more than the rest of PowerDNS, the contents of this directory are not
guaranteed to work for you.

Some scripts contain preset paths and have many many dependencies on
installed software.
