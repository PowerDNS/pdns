Compiling PowerDNS
==================

PowerDNS can be compiled with modules built in, or with modules designed to be loaded at runtime.
All that is configured before compiling using the well known autoconf/automake system::

  tar xf pdns-VERSION.tar.bz2
  cd pdns-VERSION
  ./configure --with-modules=$MODULES --with-dynmodules=$DYNMODULES
  make
  make install

To compile in modules, specify them as ``--with-modules='mod1 mod2 mod3'``, substituting the desired module names.
See each :doc:`backend specific documentation <../backends/index>` for the module names.
Each backend has a module name that you look up in this table.

To compile a module for inclusion at runtime, which is great if you are a unix vendor, use ``--with-dynmodules='mod1 mod2 mod3'``.
These modules then end up as .so files in the compiled ``libdir``.

By default, the :doc:`bind <../../backends/bind>`, :doc:`mysql <../../backends/generic-mysql>` and :doc:`random <../../backends/random>` modules are compiled into the binary. The :doc:`pipe <../../backends/pipe>` is, by default, compiled as a runtime loadable module.

Getting the sources
-------------------

There are 3 ways of getting the source.

If you want the bleeding edge, you can clone the `repository at GitHub <https://github.com/PowerDNS/pdns>`__ and run ``autoreconf -vi`` in the clone.

You can also download `snapshot tarballs <https://downloads.powerdns.com/autobuilt_browser/#/auth>`__.

You can also download releases on the `website <https://downloads.powerdns.com/releases/>`__.
These releases are PGP-signed with one of these key-ids:

.. include:: ../common/tarball-pgp-keys.rst

Dependencies
------------

To build the PowerDNS Authoritative Server, a C++ compiler with support for C++ 2017 is required.
This means gcc 7.1 and newer and clang 5 and newer.
Furthermore, the Makefiles require GNU make, not BSD make.

By default, the PowerDNS Authoritative Server requires the following libraries and headers:

* `Boost <https://boost.org/>`_ 1.54 or newer
* `OpenSSL <https://openssl.org>`_

To build from a Git repository clone, the following dependencies are also required:

* `ragel <https://www.colm.net/open-source/ragel/>`_
* `bison <https://www.gnu.org/software/bison/>`_
* `flex <https://github.com/westes/flex>`_
* `Python <https://python.org>`_ 3.6 or newer, with the 'venv' package

Optional dependencies
---------------------

Several options that can be passed to ``./configure`` can enable and disable different features.
These will require additional dependencies

ed25519 support with libsodium
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The PowerDNS Authoritative Server can link with `libsodium <https://download.libsodium.org/doc/>`_ to support ed25519 (DNSSEC algorithm 15).
To detect libsodium, use the ``--with-libsodium`` configure option.

systemd notify support
^^^^^^^^^^^^^^^^^^^^^^

During configure, ``configure`` will attempt to detect the availability of `systemd or systemd-daemon <https://freedesktop.org/wiki/Software/systemd/>`_ headers.
To force the use of systemd (and failing configure if the headers do not exist), use ``--enable-systemd``.
To set the directory where the unit files should be installed, use ``--with-systemd=/path/to/unit/dir``.
