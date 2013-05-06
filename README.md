PowerDNS is copyright Ⓒ 2012-2013 by PowerDNS.COM BV & lots of
contributors, using the GNU GPLv2 license.

This file may lag behind at times. For most recent updates, always check
http://doc.powerdns.com/changelog.html and http://wiki.powerdns.com

Another good place to look for information is:
http://doc.powerdns.com/compiling-powerdns.html

To file bugs, head towards:
https://github.com/PowerDNS/pdns/issues

But please check if the issue is already reported there first.

COMPILING
---------
PowerDNS 3.0 and beyond depend on Lua and Boost. To get these libraries,
install the relevant packages. On Debian and Ubuntu, try:

    # apt-get install g++ libboost-program-options-dev \
      libboost-serialization-dev libpqclient-dev libmysqlclient-dev \
      libsqlite3-dev libpq-dev

To compile a very clean version, use:

    $ ./configure --with-modules=""
    $ make
    # make install

This generates a PowerDNS binary with no modules, except the bind backend,
built in, and the pipe-backend available for runtime loading.

When ./configure is run without --with-modules, the gmysql module is
built-in by default and the pipe-backend is compiled for runtime loading.

To add multiple modules, try:

    $ ./configure --with-modules="gmysql gpgsql"

See http://rtfm.powerdns.com/compiling-powerdns.html for more details.

Please don't use the 'mysql' backend, it is deprecated. Use the 'gmysql'
one!

SOURCE CODE / GIT
-----------------

Source code is available on GitHub:

    $ git clone https://github.com/PowerDNS/pdns.git

SOLARIS NOTES
-------------
You need gcc 3.x, preferably 3.2! The 'Sunpro' compiler is currently not
supported (patches are welcome if not too intrusive).

If you encounter problems with the Solaris make, gmake is advised

IPv6 is broken in Solaris 2.7, use 2.8 or higher for that. PowerDNS on
Solaris 2.7 won't even serve AAAA records.

FREEBSD NOTES
-------------
gcc 2.95.x works. You need to compile using gmake - regular make only
appears to work, but doesn't in fact. Use gmake, not make.

pipebackend does not work due to bad interaction between fork and pthreads.
Amazingly, running the Linux version under the linuxulator DOES work!

MAC OS X NOTES
--------------

PowerDNS is available through Homebrew:

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

WIN32 NOTES
-----------
See http://rtfm.powerdns.com/compiling-powerdns.html#ON-WINDOWS

Needs Visual C++

---

After compiling, you may find the file 'pdns/pdns' helpful, we suggest you
place it in /etc/init.d/ or your operating system's equivalent.

