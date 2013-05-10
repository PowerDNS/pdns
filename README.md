PowerDNS is copyright Ⓒ 2012-2013 by PowerDNS.COM BV & lots of
contributors, using the GNU GPLv2 license.

All documentation can be found on http://doc.powerdns.com/

This file may lag behind at times. For most recent updates, always check
http://doc.powerdns.com/changelog.html and http://wiki.powerdns.com

Another good place to look for information is:
http://doc.powerdns.com/compiling-powerdns.html

To file bugs, head towards:
https://github.com/PowerDNS/pdns/issues

But please check if the issue is already reported there first.

SOURCE CODE / GIT
-----------------

Source code is available on GitHub:

    $ git clone https://github.com/PowerDNS/pdns.git

This repository contains the sources both for the PowerDNS Recursor and for PowerDNS Authoritative Server,
and both can be built from this repository. Both are released separately as .tar.gz, .deb and .rpm however!

COMPILING Authoritative Server
------------------------------
PowerDNS Authoritative Server 3.0 and beyond depend on Boost.

On Debian 7.0, the following is useful:

    apt-get install autoconf automake bison flex g++ git libboost-all-dev libtool make pkg-config ragel

To compile a very clean version, use:

    $ ./configure --with-modules="" --without-lua
    $ make
    # make install

This generates a PowerDNS Authoritative Server binary with no modules, except the bind backend,
built in.

When ./configure is run without --with-modules, the gmysql module is
built-in by default and the pipe-backend is compiled for runtime loading.

To add multiple modules, try:

    $ ./configure --with-modules="gmysql gpgsql"

See http://doc.powerdns.com/compiling-powerdns.html for more details.

Please don't use the 'mysql' backend, it is deprecated. Use the 'gmysql'
one!

COMPILING THE RECURSOR
----------------------
Either use ./configure --enable-recursor or explicitly do 'make pdns_recursor'. Releases
are built by first running dist-recursor and compiling from the pdns-recursor-x.y subdirectory.

SOLARIS NOTES
-------------
You need gcc 3.x, preferably 3.2! The 'Sunpro' compiler is currently not
supported (patches are welcome if not too intrusive).

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


