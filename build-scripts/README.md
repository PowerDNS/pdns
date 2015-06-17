Build Script for PowerDNS
-------------------------
The scripts in this directory are used by the folks at PowerDNS to build
packages. This README will give a small walkthrough of important files.

All `build-*` must be run from the root folder of the pdns repository to ensure
their correct functionality.

## `build-auth-*`
These scripts build (based on the suffix) a package of the authoritative
server. Either RPM's (for several different RHEL-based distro's), .deb's
(for Debian Jessie only at the moment) or statically compiled RPM's and deb's.

## `build-recursor-*`
Based on suffix, hese scripts build a deb/RPM package for the Recursor. There is
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
