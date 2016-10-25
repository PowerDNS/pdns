# Download dnsdist
dnsdist is distributed in several forms, pick the method best suited for your environment.

## Packages
dnsdist is not (yet) widely available as a package for your operating system
distribution. However, several packages are available in [our repository](https://repo.powerdns.com/).
dnsdist is known to be available on FreeBSD ports (dns/dnsdist).
Freshports link: http://www.freshports.org/dns/dnsdist/ 

## From Source
To build dnsdist, you'll need a modern C++ compiler with C++ 2011 support (like
GCC 4.8+ or clang 3.5+), GNU Make and the following libraries:

* [Boost](http://boost.org)
* [Lua](http://www.lua.org/) 5.1+ or [LuaJit](http://luajit.org/)
* Optionally: [libsodium](https://download.libsodium.org/doc/)
* Optionally: [protobuf](https://developers.google.com/protocol-buffers/)
* Optionally: [re2](https://github.com/google/re2)

To compile from git, these additional dependencies are required:

 * GNU [Autoconf](http://www.gnu.org/software/autoconf/autoconf.html)
 * GNU [Automake](https://www.gnu.org/software/automake/)
 * [Pandoc](http://pandoc.org/)
 * [Ragel](http://www.colm.net/open-source/ragel/)

### Tarballs
Release tarballs are available [here](https://downloads.powerdns.com/releases) and
snapshot tarballs are available [here](https://downloads.powerdns.com/autobuilt/dnsdist/dist/).

 * Untar the tarball
 * `./configure`
 * `make`

## From git
dnsdist can be built from the [PowerDNS repository](https://github.com/PowerDNS/pdns/)
(but is independent of PowerDNS)

 * `git clone https://github.com/PowerDNS/pdns.git`
 * `cd pdns/pdns/dnsdistdist`
 * `autoreconf -i`
 * `./configure`
 * `make`
