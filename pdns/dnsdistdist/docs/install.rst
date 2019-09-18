Installing dnsdist
==================

dnsdist only runs on UNIX-like systems and there are several ways to install dnsdist.
The fastest way is using packages, either from your own operating system vendor or suppied by the PowerDNS project.
Building from source is also supported.


Installing from Packages
------------------------

If dnsdist is available in your operating system's software repositories, install it from there.
However, the version of dnsdist in the repositories might be an older version that might not have a feature that was added in a later version.
Or you might want to be brave and try a development snapshot from the master branch.
PowerDNS provides software respositories for the most popular distributions.
Visit https://repo.powerdns.com for more information and installation instructions.

Debian
~~~~~~

For Debian and its derivatives (like Ubuntu) installing the ``dnsdist`` package should do it:

.. code-block:: sh

  apt-get install -y dnsdist

RedHat
~~~~~~

For RedHat, CentOS and its derivatives, dnsdist is available in `EPEL <https://fedoraproject.org/wiki/EPEL>`_:

.. code-block:: sh

  yum install -y epel-release
  yum install -y dnsdist

FreeBSD
~~~~~~~

dnsdist is also available in `FreeBSD ports <http://www.freshports.org/dns/dnsdist/>`_.

Installing from Source
----------------------

In order to compile dnsdist, a modern compiler with C++ 2011 support (like GCC 4.8+ or clang 3.5+) and GNU make are required.
dnsdist depends on the following libraries:

* `Boost <http://boost.org/>`_
* `Lua <http://www.lua.org/>`_ 5.1+ or `LuaJit <http://luajit.org/>`_
* `Editline (libedit) <http://thrysoee.dk/editline/>`_
* `libsodium <https://download.libsodium.org/doc/>`_ (optional)
* `protobuf <https://developers.google.com/protocol-buffers/>`_ (optional)
* `re2 <https://github.com/google/re2>`_ (optional)

Should :program:`dnsdist` be run on a system with systemd, it is highly recommended to have
the systemd header files (``libsystemd-dev`` on Debian and ``systemd-devel`` on CentOS)
installed to have :program:`dnsdist` support ``systemd-notify``.

From tarball
~~~~~~~~~~~~

Release tarballs are available `from the downloads site <https://downloads.powerdns.com/releases>`_, snapshot and pre-release tarballs `can be found as well <https://downloads.powerdns.com/autobuilt_browser/#/dnsdist>`__.

The release tarballs have detached PGP signatures, signed by one of these PGP keys:

* `D630 0CAB CBF4 69BB E392 E503 A208 ED4F 8AF5 8446 <https://pgp.mit.edu/pks/lookup?op=get&search=0xA208ED4F8AF58446>`__
* `FBAE 0323 821C 7706 A5CA 151B DCF5 13FA 7EED 19F3 <https://pgp.mit.edu/pks/lookup?op=get&search=0xDCF513FA7EED19F3>`__
* `1628 90D0 689D D12D D33E 4696 1C5E E990 D2E7 1575 <https://pgp.mit.edu/pks/lookup?op=get&search=0x1C5EE990D2E71575>`__
* `B76C D467 1C09 68BA A87D E61C 5E50 715B F2FF E1A7 <https://pgp.mit.edu/pks/lookup?op=get&search=0x5E50715BF2FFE1A7>`__
* `16E1 2866 B773 8C73 976A 5743 6FFC 3343 9B0D 04DF <https://pgp.mit.edu/pks/lookup?op=get&search=0x6FFC33439B0D04DF>`__

There is a PGP keyblock with these keys available on `https://dnsdist.org/_static/dnsdist-keyblock.asc <https://dnsdist.org/_static/dnsdist-keyblock.asc>`__.

* Untar the tarball and ``cd`` into the source directory
* Run ``./configure``
* Run ``make`` or ``gmake`` (on BSD)

From git
~~~~~~~~

To compile from git, these additional dependencies are required:

* GNU `Autoconf <http://www.gnu.org/software/autoconf/autoconf.html>`_
* GNU `Automake <https://www.gnu.org/software/automake/>`_
* `Ragel <http://www.colm.net/open-source/ragel/>`_

dnsdist source code lives in the `PowerDNS git repository <https://github.com/PowerDNS/pdns>`_ but is independent of PowerDNS.

::

  git clone https://github.com/PowerDNS/pdns.git
  cd pdns/pdns/dnsdistdist
  autoreconf -i
  ./configure
  make

OS Specific Instructions
~~~~~~~~~~~~~~~~~~~~~~~~

None, really.
