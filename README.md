PowerDNS is copyright Ⓒ 2002-2015 by PowerDNS.COM BV and lots of
contributors, using the GNU GPLv2 license (see NOTICE for the
exact license and exception used).

All documentation can be found on http://doc.powerdns.com/

This file may lag behind at times. For most recent updates, always check
https://doc.powerdns.com/md/changelog/ and http://wiki.powerdns.com

Another good place to look for information is:
https://doc.powerdns.com/md/appendix/compiling-powerdns/

To file bugs, head towards:
https://github.com/PowerDNS/pdns/issues

But please check if the issue is already reported there first.

SOURCE CODE / GIT
-----------------

Source code is available on GitHub:

    $ git clone https://github.com/PowerDNS/pdns.git
    
This repository contains the sources both for the PowerDNS Recursor and for PowerDNS Authoritative Server,
and both can be built from this repository. Both are released separately as .tar.bz2, .deb and .rpm however!

COMPILING Authoritative Server
------------------------------
PowerDNS Authoritative Server 3.0 and beyond depend on Boost.

On Debian 7.0, the following is useful:

    apt-get install autoconf automake bison flex g++ git libboost-all-dev libtool make pkg-config ragel libmysqlclient-dev

If you build from git, first build configure:

    $ ./bootstrap

(You may need to do that twice. You also need libtool-1.4, 1.3 won't work.
Autoconf 2.61 or newer and Automake 1.11 or newer are required, too.)

To compile a very clean version, use:

    $ ./configure --with-modules="" --without-lua
    $ make
    # make install

This generates a PowerDNS Authoritative Server binary with no modules built in.

When `./configure` is run without `--with-modules`, the bind and gmysql module are
built-in by default and the pipe-backend is compiled for runtime loading.

To add multiple modules, try:

    $ ./configure --with-modules="bind gmysql gpgsql"

See http://doc.powerdns.com/compiling-powerdns.html for more details.

COMPILING THE RECURSOR
----------------------
On Linux, `make pdns_recursor` in the `pdns` subdir may work. The portable, and supported, way to
build the recursor is first running `dist-recursor` and compiling from the `pdns-recursor-x.y` subdirectory.

When building from git `pandoc` and `zip` are build dependencies. 

To build deb and rpm packages after running `dist-recursor`, run `build-recursor`. This depends on
Lua 5.1 (liblua5.1-dev), dh-make and rpm.

SOLARIS NOTES
-------------
Use a recent gcc. OpenCSW is a good source, as is Solaris 11 IPS.

If you encounter problems with the Solaris make, gmake is advised.

FREEBSD NOTES
-------------
You need to compile using gmake - regular make only appears to work, but doesn't in fact. Use gmake, not make.

MAC OS X NOTES
--------------

PowerDNS Authoritative Server is available through Homebrew:

    $ brew install pdns

If you want to compile yourself, the dependencies can be installed using
Homebrew:

    $ brew install boost lua pkg-config ragel

For PostgreSQL support:

    $ brew install postgresql

For MySQL support:

    $ brew install mariadb

LINUX NOTES
-----------
None really.


