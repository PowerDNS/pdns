Compiling the PowerDNS Recursor
===============================

As the PowerDNS Recursor is distributed with a configure script, compiling it is a matter of::

  tar xf pdns-recursor-$VERSION.tar.bz2
  cd pdns-recursor-$VERSION
  ./configure
  make
  make install

Getting the sources
-------------------

There are 3 ways of getting the source.

If you want the bleeding edge, you can clone the `repository at GitHub <https://github.com/PowerDNS/pdns>`__ and run ``autoreconf -vi`` in the ``pdns/recursordist`` directory of the clone.

You can also download snapshot tarballs `here <https://downloads.powerdns.com/autobuilt_browser/#/recursor>`__.

You can also download releases on the `website <https://downloads.powerdns.com/releases/>`__.
These releases are PGP-signed with one of these key-ids:

.. include:: ../common/tarball-pgp-keys.rst

Dependencies
------------

To build the PowerDNS Recursor, a C++ compiler with support for C++ 2011 is required.
This means gcc 4.9 and newer and clang 3.5 and newer.
Furthermore, the Makefiles require GNU make, not BSD make.

By default, the PowerDNS recursor requires the following libraries and headers:

* `Boost <http://boost.org/>`_ 1.35 or newer
* `Lua <http://www.lua.org/>`_ 5.1+ or `LuaJit <http://luajit.org/>`_
* `OpenSSL <https://openssl.org>`_

Optional dependencies
---------------------

Several options that can be passed to ``./configure`` can enable and disable different features.
These will require additional dependencies

ed25519 support with libsodium
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The PowerDNS Recursor can link with `libsodium <https://download.libsodium.org/doc/>`_ to support ed25519 (DNSSEC algorithm 15).
To detect libsodium, use the ``--with-libsodium`` configure option.

.. versionchanged:: 4.2.0
  This option was previously ``--enable-libsodium``

ed25519 and ed448 support with libdecaf
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`libdecaf <https://sourceforge.net/projects/ed448goldilocks/>`_ is a library that allows the PowerDNS Recursor to support ed25519 and Ed448 (DNSSEC algorithms 15 and 16).
To detect libdecaf, use the ``--with-libdecaf`` configure option.

.. versionchanged:: 4.2.0
  This option was previously ``--enable-libdecaf``

Protobuf to emit DNS logs
^^^^^^^^^^^^^^^^^^^^^^^^^

The PowerDNS Recursor can log DNS query information over :doc:`Protocol Buffers <../lua-config/protobuf>`.
To enable this functionality, install the  `protobuf <https://developers.google.com/protocol-buffers/>`_ library and compiler.
The configure script will automatically detect this and bump the Boost version depencency to 1.42.

To disable building this functionality, use ``--without-protobuf``.

systemd notify support
^^^^^^^^^^^^^^^^^^^^^^

During configure, ``configure`` will attempt to detect the availibility of `systemd or systemd-daemon <https://freedesktop.org/wiki/Software/systemd/>`_ headers.
To force the use of systemd (and failing configure if the headers do not exist), use ``--enable-systemd``.
To set the directory where the unit files should be installed, use ``--with-systemd=/path/to/unit/dir``.
