PowerDNS is copyright © 2001-2019 by PowerDNS.COM BV and lots of
contributors, using the GNU GPLv2 license (see NOTICE for the
exact license and exception used).

All documentation can be found on https://doc.powerdns.com/

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

The different releases can be built by the help of pdns-builder, which uses a
docker-based build process. To get started with this, run these commands in the root
of this repository:

```sh
git submodule init
git submodule update
./builder/build.sh
```

This will bring up a USAGE-page which will explain how to build the different releases.

COMPILING Authoritative Server
------------------------------
The PowerDNS Authoritative Server depends on Boost, OpenSSL and requires a
compiler with C++-2011 support.

On Debian 9, the following is useful:

```sh
apt install g++ libboost-all-dev libtool make pkg-config default-libmysqlclient-dev libssl-dev virtualenv
```

When building from git, the following packages are also required:

```sh
apt install autoconf automake ragel bison flex
```

For Ubuntu 18.04 (Bionic Beaver), the following packages should be installed:

```sh
apt install libcurl4-openssl-dev luajit lua-yaml-dev libyaml-cpp-dev libtolua-dev lua5.3 autoconf automake ragel bison flex g++ libboost-all-dev libtool make pkg-config libssl-dev virtualenv lua-yaml-dev libyaml-cpp-dev libluajit-5.1-dev libcurl4 gawk
# For DNSSEC ed25519 (algorithm 15) support with --with-libsodium
apt install libsodium-dev
# If using the gmysql (Generic MySQL) backend
apt install default-libmysqlclient-dev
# If using the gpgsql (Generic PostgreSQL) backend
apt install postgresql-server-dev-10
# If using --enable-systemd (will create the service scripts so it can be managed with systemctl/service)
apt install libsystemd0 libsystemd-dev
# If using the geoip backend
apt install libmaxminddb-dev libmaxminddb0 libgeoip1 libgeoip-dev
```

Then generate the configure file:

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

See https://doc.powerdns.com/authoritative/backends/index.html for a list of available modules.

When `./configure` is run without `--with-modules`, the bind and gmysql module are
built-in by default and the pipe-backend is compiled for runtime loading.

To add multiple modules, try:

```sh
./configure --with-modules="bind gmysql gpgsql"
```

Note that you will need the development headers for PostgreSQL as well in this case.

See https://doc.powerdns.com/authoritative/appendices/compiling.html for more details.

If you run into C++11-related symbol trouble, please try passing `CPPFLAGS=-D_GLIBCXX_USE_CXX11_ABI=0` (or 1) to `./configure` to make sure you are compatible with the installed dependencies.

Compiling the Recursor
----------------------
See [README.md](pdns/recursordist/README.md) in `pdns/recursordist/`.

Compiling dnsdist
-----------------
See [README-dnsdist.md](pdns/README-dnsdist.md) in `pdns/`.

Building the HTML documentation
-------------------------------

The HTML documentation (as seen [on the PowerDNS docs site](https://doc.powerdns.com/authoritative/)) is built from ReStructured Text (rst) files located in `docs`. They are compiled into HTML files using [Sphinx](http://www.sphinx-doc.org/en/master/index.html), a documentation generator tool which is built in Python.

**Using a normal Python installation**

For those simply contributing to the documentation, this avoids needing to install the various build
tools and other dependencies.

Install Python 2.7 or Python 3 (preferable) if you don't yet have it installed. On some operating
systems you may also have to install `python3-pip` or similarly named.

Ubuntu 16.04 / 18.04

```sh
apt update
apt install python3 python3-pip python3-venv
```

macOS (using homebrew)

```sh
brew install python3
```

Update your `pip` and install/update `virtualenv` to avoid problems:

```sh
# for python2, use "pip" instead of "pip3"
pip3 install -U pip
pip3 install -U virtualenv
```

Enter the repository's `docs` folder, set up the virtualenv, and install the requirements

```sh
cd docs
# for python2, use "virtualenv .venv" instead
python3 -m venv .venv
source .venv/bin/activate
# The virtualenv may use an older pip, so upgrade it again
pip3 install -U pip setuptools setuptools-git
# Now you can install the requirements
pip3 install -r requirements.txt
```

Finally, you can build the documentation:

```sh
sphinx-build . html-docs
```

Note: If your shell has problems finding sphinx-build, try using `.venv/bin/sphinx-build` instead.

The HTML documentation is now available in `html-docs`.

**Using the build tools**

This method is preferable for those who already have a working build environment for PowerDNS.

Install the dependencies under "COMPILING", and run autoreconf if you haven't already:

```sh
autoreconf -vi
```

Enter the `docs` folder, and use make to build the HTML docs.

```
cd docs
make html-docs
```

The HTML documentation will now be available in `html-docs`.

Solaris Notes
-------------
Use a recent gcc (and other build tools), possibly from Solaris 11 IPS.

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

Additionally, for PostgreSQL support, run `brew install postgresql` and add `--with-modules="gpgsql"` to `./configure`.
For MySQL support, run `brew install mariadb` and add `--with-modules="gmysql"` to `./configure`.

Linux notes
-----------
None really.
