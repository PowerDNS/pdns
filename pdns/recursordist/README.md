PowerDNS Recursor
-----------------
For full details, please read https://doc.powerdns.com/md/recursor/

Here follow some brief notes that may be useful to get you going.

Compiling
---------
Starting with version 4.0.0, the PowerDNS recursor uses autotools and compiling
[from the tarball](https://downloads.powerdns.com/releases/) can be as simple as

```sh
./configure
make
```

As for dependencies, Boost (http://boost.org/), OpenSSL (https://openssl.org/),
and Lua (https://www.lua.org/) are required.

On most modern UNIX distributions, you can simply install 'boost' or
'boost-dev' or 'boost-devel'. Otherwise, just download boost, and point the
compiler at the right directory using CPPFLAGS.

On Debian and Ubuntu, the following will get you the dependencies:

```sh
apt-get install libboost-dev libboost-serialization-dev libboost-system-dev libboost-thread-dev libboost-context-dev libssl-dev g++ make pkg-config libluajit-5.1-dev
```

Compiling from git checkout
===========================
Source code is available on GitHub:

```sh
git clone https://github.com/PowerDNS/pdns.git
```

This repository contains the sources for the PowerDNS Recursor, the PowerDNS
Authoritative Server, and dnsdist (a powerful DNS loadbalancer). The sources for
the recursor are located in the `pdns/recursordist` subdirectory of the repository.

To compile from a git checkout, install ragel, automake, autoconf, libtool and curl.
Then run

```sh
cd pdns/pdns/recursordist/
autoreconf -vi
./configure
make
```

macOS Notes
-----------

If you want to compile yourself, the dependencies can be installed using
Homebrew. You need to tell configure where to find OpenSSL, too.

```sh
brew install boost lua pkg-config ragel openssl
./configure --with-lua PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig
make -j4
```

Lua scripting
-------------
To benefit from Lua scripting, as described on https://doc.powerdns.com/md/recursor/scripting/
Install Lua and development headers. PowerDNS supports Lua 5.1, 5.2, 5.3 and LuaJIT.
On Debian/Ubuntu, install e.g. `liblua5.2-dev` to use Lua 5.2.

The configure script will automatically detect the Lua version. If more than one
version of Lua is installed, the `--with-lua` configure flag can be set to the
desired version. e.g.:

```sh
./configure --with-lua=lua51
```

(On older versions of Debian/Ubuntu, you'll need to pass `--with-lua=lua5.1` instead.)

Documentation
-------------
After compiling, run `pdns\_recursor --config` to view the configuration options
and a short description. The full documentation is online at
https://doc.powerdns.com/recursor/

Reporting bugs
--------------
Bugs can be reported on GitHub: https://github.com/PowerDNS/pdns/issues, please
check first if your issue is not fixed in the latest version or has already been
reported.

License
-------
PowerDNS is copyright © 2001-2019 by PowerDNS.COM BV and lots of
contributors, using the GNU GPLv2 license (see NOTICE for the
exact license and exception used).
