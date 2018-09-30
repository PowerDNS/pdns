PowerDNS is copyright © 2001-2018 by PowerDNS.COM BV and lots of
contributors, using the GNU GPLv2 license (see NOTICE for the
exact license and exception used).

All documentation can be found on http://doc.powerdns.com/

This file may lag behind at times. For most recent updates, always check
https://doc.powerdns.com/md/changelog/.

Another good place to look for information is:
https://doc.powerdns.com/md/appendix/compiling-powerdns/

To file bugs, head towards:
https://github.com/PowerDNS/pdns/issues

But please check if the issue is already reported there first.

SOURCE CODE / GIT
-----------------
Source code is available on GitHub:

```sh
git clone https://github.com/PowerDNS/pdns.git
```

This repository contains the sources for the PowerDNS Recursor, the PowerDNS
Authoritative Server, and dnsdist (a powerful DNS loadbalancer). All three can
be built from this repository. However, all three released separately as .tar.bz2,
.deb and .rpm.

COMPILING Authoritative Server
------------------------------
The PowerDNS Authoritative Server depends on Boost, OpenSSL and requires a
compiler with C++-2011 support.

On Debian 8.0, the following is useful:

```sh
apt-get install g++ libboost-all-dev libtool make pkg-config libmysqlclient-dev libssl-dev virtualenv
```

When building from git, the following packages are also required: autoconf, automake,
ragel, bison and flex, then generate the configure file:

```sh
autoreconf -vi
```

To compile a very clean version, use:

```sh
./configure --with-modules="" --without-lua --disable-lua-records
make
# make install
```

This generates a PowerDNS Authoritative Server binary with no modules built in.

When `./configure` is run without `--with-modules`, the bind and gmysql module are
built-in by default and the pipe-backend is compiled for runtime loading.

To add multiple modules, try:

```sh
./configure --with-modules="bind gmysql gpgsql"
```

Note that you will need the development headers for PostgreSQL as well in this case.

See https://doc.powerdns.com/md/appendix/compiling-powerdns/ for more details.

If you run into C++11-related symbol trouble, please try passing `CPPFLAGS=-D_GLIBCXX_USE_CXX11_ABI=0` (or 1) to `./configure` to make sure you are compatible with the installed dependencies.

Compiling the Recursor
----------------------
See the README in pdns/recursordist.

Compiling dnsdist
-----------------
See the README in pdns/dnsdistdist.

Solaris Notes
-------------
Use a recent gcc. OpenCSW is a good source, as is Solaris 11 IPS.

If you encounter problems with the Solaris make, gmake is advised.

FreeBSD Notes
-------------
You need to compile using gmake - regular make only appears to work, but doesn't in fact. Use gmake, not make.

The clang compiler installed through FreeBSD's package manager does not expose all of the C++11 features needed under `std=gnuc++11`. Force the compiler to use `std=c++11` mode instead.

```sh
export CXXFLAGS=-std=c++11
```

macOS Notes
-----------
PowerDNS Authoritative Server is available through Homebrew:

```
brew install pdns
```

If you want to compile yourself, the dependencies can be installed using
Homebrew. You need to tell configure where to find OpenSSL, too.

```sh
brew install boost lua pkg-config ragel openssl
./configure --with-modules="" --with-lua PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig
make -j4
```

Additionally, for PostgreSQL support, run `brew install postgresql` and add `--with-modules="gpsql"` to `./configure`.
For MySQL support, run `brew install mariadb` and add `--with-modules="gmysql"` to `./configure`.

Linux notes
-----------
None really.
