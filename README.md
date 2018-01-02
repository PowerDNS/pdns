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

```
$ git clone https://github.com/PowerDNS/pdns.git
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

```
$ apt-get install g++ libboost-all-dev libtool make pkg-config libmysqlclient-dev libssl-dev
```

When building from git, the following packages are also required: autoconf, automake,
ragel, bison and flex, then generate the configure file:

```
$ ./bootstrap
```

To compile a very clean version, use:

```
$ ./configure --with-modules="" --without-lua
$ make
# make install
```

This generates a PowerDNS Authoritative Server binary with no modules built in.

When `./configure` is run without `--with-modules`, the bind and gmysql module are
built-in by default and the pipe-backend is compiled for runtime loading.

To add multiple modules, try:

```
$ ./configure --with-modules="bind gmysql gpgsql"
```

Note that you will need the development headers for PostgreSQL as well in this case.

See https://doc.powerdns.com/md/appendix/compiling-powerdns/ for more details.

If you run into C++11-related symbol trouble, please try passing `CPPFLAGS=-D_GLIBCXX_USE_CXX11_ABI=0` (or 1) to `./configure` to make sure you are compatible with the installed dependencies.

On macOS, you may need to `brew install openssl` and set `PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig` during configure.

COMPILING THE RECURSOR
----------------------
See the README in pdns/recursordist.

COMPILING DNSDIST
----------------------
See the README in pdns/dnsdistdist.

SOLARIS NOTES
-------------
Use a recent gcc. OpenCSW is a good source, as is Solaris 11 IPS.

If you encounter problems with the Solaris make, gmake is advised.

FREEBSD NOTES
-------------
You need to compile using gmake - regular make only appears to work, but doesn't in fact. Use gmake, not make.

The clang compiler installed through FreeBSD's package manager does not expose all of the C++11 features needed under `std=gnuc++11`. Force the compiler to use `std=c++11` mode instead.

    export CXXFLAGS=-std=c++11

MAC OS X NOTES
--------------
PowerDNS Authoritative Server is available through Homebrew:

```
$ brew install pdns
```

If you want to compile yourself, the dependencies can be installed using
Homebrew:

```
$ brew install boost lua pkg-config ragel
```

For PostgreSQL support:

```
$ brew install postgresql
```

For MySQL support:

```
$ brew install mariadb
```

LINUX NOTES
-----------
None really.
