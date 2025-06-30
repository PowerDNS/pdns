Installing dnsdist
==================

dnsdist only runs on UNIX-like systems and there are several ways to install dnsdist.
The fastest way is using packages, either from your own operating system vendor or supplied by the PowerDNS project.
Building from source is also supported.


Installing from Packages
------------------------

If dnsdist is available in your operating system's software repositories, you can install it from there.
However, the version of dnsdist in the repositories might be an older version that might not have a feature that was added in a later version.
Or you might want to be brave and try a development snapshot from the master branch.
PowerDNS provides software repositories for the most popular distributions.
Visit https://repo.powerdns.com for more information and installation instructions.

Debian
~~~~~~

For Debian and its derivatives (like Ubuntu) installing the ``dnsdist`` package should do it:

.. code-block:: sh

  apt-get install -y dnsdist

Red Hat
~~~~~~~

For Red Hat, CentOS and its derivatives, dnsdist is available in `EPEL <https://fedoraproject.org/wiki/EPEL>`_:

.. code-block:: sh

  yum install -y epel-release
  yum install -y dnsdist

FreeBSD
~~~~~~~

dnsdist is also available in `FreeBSD ports <http://www.freshports.org/dns/dnsdist/>`_.

Installing from Source
----------------------

In order to compile dnsdist, a modern compiler with C++ 2017 support, a Python 3 interpreter with the ``YAML`` module, and either GNU make or ``meson`` with ``ninja`` are required.
dnsdist depends on the following libraries:

* `Boost <http://boost.org/>`_
* `Lua <http://www.lua.org/>`_ 5.1+ or `LuaJit <http://luajit.org/>`_
* `Editline (libedit) <http://thrysoee.dk/editline/>`_
* `libfstrm <https://github.com/farsightsec/fstrm>`_ (optional, dnstap support)
* `GnuTLS <https://www.gnutls.org/>`_ (optional, DoT and DoH support)
* `hostname from Inetutils <https://www.gnu.org/software/inetutils/>`_
  (required for building with ``meson``)
* `libbpf <https://github.com/libbpf/libbpf>`_ and `libxdp <https://github.com/xdp-project/xdp-tools>`_ (optional, `XSK`/`AF_XDP` support)
* `libcap <https://sites.google.com/site/fullycapable/>`_ (optional, capabilities support)
* `libh2o <https://github.com/h2o/h2o>`_ (optional, incoming DoH support, deprecated in 1.9.0 in favor of ``nghttp2``)
* `libsodium <https://download.libsodium.org/doc/>`_ (optional, DNSCrypt support)
* `LMDB <http://www.lmdb.tech/doc/>`_ (optional, LMDB support)
* `net-snmp <http://www.net-snmp.org/>`_ (optional, SNMP support)
* `nghttp2 <https://nghttp2.org/>`_ (optional, DoH support)
* `OpenSSL <https://www.openssl.org/>`_ (optional, DoT and DoH support)
* `Quiche <https://github.com/cloudflare/quiche>`_ (optional, incoming DoQ and DoH3 support)
* `re2 <https://github.com/google/re2>`_ (optional)
* `TinyCDB <https://www.corpit.ru/mjt/tinycdb.html>`_ (optional, CDB support)

Since 2.0.0, the optional ``yaml`` configuration requires a Rust development environment, including ``rustc`` and ``cargo``.

Should :program:`dnsdist` be run on a system with systemd, it is highly recommended to have
the systemd header files (``libsystemd-dev`` on Debian and ``systemd-devel`` on CentOS)
installed to have :program:`dnsdist` support ``systemd-notify``.

From tarball
~~~~~~~~~~~~

Release tarballs are available `from the downloads site <https://downloads.powerdns.com/releases>`_, snapshot and pre-release tarballs `can be found as well <https://downloads.powerdns.com/autobuilt_browser/#/dnsdist>`__.

The release tarballs have detached PGP signatures, signed by one of these PGP keys:

* `FBAE 0323 821C 7706 A5CA 151B DCF5 13FA 7EED 19F3 <https://pgp.mit.edu/pks/lookup?op=get&search=0xDCF513FA7EED19F3>`_
* `D630 0CAB CBF4 69BB E392 E503 A208 ED4F 8AF5 8446 <https://pgp.mit.edu/pks/lookup?op=get&search=0xA208ED4F8AF58446>`_
* `16E1 2866 B773 8C73 976A 5743 6FFC 3343 9B0D 04DF <https://pgp.mit.edu/pks/lookup?op=get&search=0x6FFC33439B0D04DF>`_
* `990C 3D0E AC7C 275D C6B1 8436 EACA B90B 1963 EC2B <https://pgp.mit.edu/pks/lookup?op=get&search=0xEACAB90B1963EC2B>`_

There is a PGP keyblock with these keys available on `https://dnsdist.org/_static/dnsdist-keyblock.asc <https://dnsdist.org/_static/dnsdist-keyblock.asc>`__.

Older (1.0.x) releases can also be signed with one of the following keys:

* `1628 90D0 689D D12D D33E 4696 1C5E E990 D2E7 1575 <https://pgp.mit.edu/pks/lookup?op=get&search=0x1C5EE990D2E71575>`_
* `B76C D467 1C09 68BA A87D E61C 5E50 715B F2FF E1A7 <https://pgp.mit.edu/pks/lookup?op=get&search=0x5E50715BF2FFE1A7>`_

To compile from tarball:

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

Using meson
~~~~~~~~~~~

dnsdist can also be compiled with ``meson`` and ``ninja``. For example::

  meson setup build
  meson compile -C build

OS Specific Instructions
~~~~~~~~~~~~~~~~~~~~~~~~

None, really.

Build options
~~~~~~~~~~~~~

Our ``configure`` script and ``meson_options.txt`` counterpart provides a fair number of options with regard to which features should be enabled, as well as which libraries should be used. Run ``./configure --help`` or ``meson configure`` for the list of supported options.

In addition to these options, more features can be disabled at compile-time by defining the following symbols:

* ``DISABLE_BUILTIN_HTML`` removes the built-in web pages
* ``DISABLE_CARBON`` for carbon support
* ``DISABLE_COMPLETION`` for completion support in the console
* ``DISABLE_DELAY_PIPE`` removes the ability to delay UDP responses
* ``DISABLE_DEPRECATED_DYNBLOCK`` for legacy dynamic blocks not using the new ``DynBlockRulesGroup`` interface
* ``DISABLE_DYNBLOCKS`` disables the new dynamic block interface
* ``DISABLE_ECS_ACTIONS`` to disable actions altering EDNS Client Subnet
* ``DISABLE_FALSE_SHARING_PADDING`` to disable the padding of atomic counters, which is inserted to prevent false sharing but increases the memory use significantly
* ``DISABLE_HASHED_CREDENTIALS`` to disable password-hashing support
* ``DISABLE_LUA_WEB_HANDLERS`` for custom Lua web handlers support
* ``DISABLE_OCSP_STAPLING`` for OCSP stapling
* ``DISABLE_OPENSSL_ERROR_STRINGS`` to disable the loading of OpenSSL's error strings, reducing the memory use at the cost of human-readable error messages
* ``DISABLE_NPN`` for Next Protocol Negotiation, superseded by ALPN
* ``DISABLE_PROMETHEUS`` for prometheus
* ``DISABLE_PROTOBUF`` for protocol-buffer support, including dnstap
* ``DISABLE_RECVMMSG`` for ``recvmmsg`` support
* ``DISABLE_RULES_ALTERING_QUERIES`` to remove rules altering the content of queries
* ``DISABLE_SECPOLL`` for security polling
* ``DISABLE_WEB_CACHE_MANAGEMENT`` to disable cache management via the API
* ``DISABLE_WEB_CONFIG`` to disable accessing the configuration via the web interface

Additionally several Lua bindings can be removed when they are not needed, as they increase the memory required during compilation and the size of the final binary:

* ``DISABLE_CLIENT_STATE_BINDINGS``
* ``DISABLE_COMBO_ADDR_BINDINGS``
* ``DISABLE_DNSHEADER_BINDINGS``
* ``DISABLE_DNSNAME_BINDINGS``
* ``DISABLE_DOWNSTREAM_BINDINGS``
* ``DISABLE_NETMASK_BINDINGS``
* ``DISABLE_NON_FFI_DQ_BINDINGS``
* ``DISABLE_PACKETCACHE_BINDINGS``
* ``DISABLE_POLICIES_BINDINGS``
* ``DISABLE_QPS_LIMITER_BINDINGS``
* ``DISABLE_SUFFIX_MATCH_BINDINGS``
* ``DISABLE_TOP_N_BINDINGS``

Finally a build flag can be used to make use a single thread to handle all incoming UDP queries from clients, no matter how many :func:`addLocal` directives are present in the configuration. It also moves the task of accepting incoming TCP connections to the TCP workers themselves, removing the TCP acceptor threads. This option is destined to resource-constrained environments where dnsdist needs to listen on several addresses, over several interfaces, and one thread is enough to handle the traffic and therefore the overhead of using multiples threads for that task does not make sense.
This option can be enabled by setting ``USE_SINGLE_ACCEPTOR_THREAD``.
