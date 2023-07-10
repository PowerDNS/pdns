BIND zone file backend
======================

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: Experimental
* DNSSEC: Yes
* Disabled data: No
* Comments: No
* API: Read-only
* Zone caching: Yes (except in hybrid mode)
* Module name: bind
* Launch: ``bind``

The BIND backend started life as a demonstration of the versatility of
PowerDNS but quickly gained in importance when there appeared to be
demand for a BIND 'work-alike'.

The BIND backend parses a BIND-style ``named.conf`` and extracts
information about zones from it. It makes no attempt to honour other
configuration flags, which you should configure (when available) using
the PowerDNS native configuration.

Unique to this PowerDNS backend is that it serves from plain zone files,
which allows for hand-crafting zone files, only takes a tiny footprint
in terms of server resource usage while being
:ref:`performant efficiently <bind_performance>`.

.. note::
  Because this backend retrieves its configuration from plain files and
  not a database, the HTTP API is unable to process changes for this
  backend. This effectively makes the API read-only for zones hosted by
  the BIND backend.

Configuration Parameters
------------------------

.. _setting-bind-config:

``bind-config``
~~~~~~~~~~~~~~~

Location of the BIND configuration file to parse.

PowerDNS does not support every directive supported by BIND.
It supports the following blocks and directives:

* ``options``
   * ``directory``
   * ``also-notify``
* ``zone``
   * ``file``
   * ``type``
   * ``masters``
   * ``also-notify``

.. _setting-bind-check-interval:

``bind-check-interval``
~~~~~~~~~~~~~~~~~~~~~~~

Interval in seconds to check for zone file changes. Default is 0 (disabled).

See :ref:`bind-operation` section for more information.

.. _setting-bind-dnssec-db:

``bind-dnssec-db``
~~~~~~~~~~~~~~~~~~

Filename to store and access our DNSSEC metadatabase, empty for none. To
slave DNSSEC-enabled domains (where the RRSIGS are in the AXFR), a
``bind-dnssec-db`` is required. This is because the
:ref:`metadata-presigned` domain metadata is set
during the zonetransfer.

You can use ``pdnsutil create-bind-db`` to make this database file for you.

.. warning::
   If this is left empty on slaves and a presigned zone is transferred,
   it will (silently) serve it without DNSSEC. This in turn results in
   serving the domain as bogus.

.. _setting-bind-dnssec-db-journal-mode:

``bind-dnssec-db-journal-mode``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SQLite3 journal mode to set. The default is WAL. Set to empty to leave the journal mode alone.

.. _setting-bind-hybrid:

``bind-hybrid``
~~~~~~~~~~~~~~~

Store DNSSEC keys and metadata storage in another backend. See the
:ref:`dnssec-modes-hybrid-bind` documentation.

.. _setting-bind-ignore-broken-records:

``bind-ignore-broken-records``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Setting this option to ``yes`` makes PowerDNS ignore out of zone records
when loading zone files.

.. _setting-bind-supermasters:

``bind-supermasters``
~~~~~~~~~~~~~~~~~~~~~

Specifies file where to read list of autoprimaries.
BIND backend only checks IP address of primary server.

The file must contain one IP and account per line, separated by whitespace.

BIND backend can only read this file, not write it.

.. _setting-bind-supermaster-config:

``bind-supermaster-config``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a new zone is configured via the autosecondary mechanism, bindbackend *writes* a zone entry to this file.

Your ``bind-config`` file should have an ``include`` statement to make sure this file is read on startup.

.. _setting-bind-supermaster-destdir:

``bind-supermaster-destdir``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each new zone configured via the autosecondary mechanism gets a zone file in this directory.
This directory must be writable.

.. _bind-operation:

Operation
---------

On launch, the BIND backend first parses the ``named.conf`` to determine
which zones need to be loaded. These will then be parsed and made
available for serving, as they are parsed. So a ``named.conf`` with
100.000 zones may take 20 seconds to load, but after 10 seconds, 50.000
zones will already be available. While a domain is being loaded, it is
not yet available, to prevent incomplete answers.

Reloading is currently done only when a request (or zone transfer) for a
zone comes in, and then only after :ref:`setting-bind-check-interval`
seconds have passed after the last check. If a change occurred, access
to the zone is disabled, the file is reloaded, access is restored, and
the question is answered. For regular zones, reloading is fast enough to
answer the question which lead to the reload within the DNS timeout.

If :ref:`setting-bind-check-interval` is specified as
zero, no checks will be performed until the ``pdns_control reload`` is
given.

Please note that also the :ref:`setting-slave-cycle-interval` setting
controls how often a master would notify a slave about changes.
Especially in 'hidden master' configurations, where servers usually
don't receive regular queries, you may want to lower that setting to a
value as low as :ref:`setting-bind-check-interval`.

pdns\_control commands
----------------------

``bind-add-zone <domain> <filename>``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add zone ``domain`` from ``filename`` to PowerDNS's BIND backend. Zone
will be loaded at first request.

.. note::
  This does not add the zone to the :ref:`setting-bind-config` file.

``bind-domain-extended-status [domain ...]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 4.3.0

Output an extended status of a domain or domains, containing much more information than
the simple domain status, like the number of records currently loaded, whether pdns
is master or slave for the domain, the list of masters, various timers, etc

``bind-domain-status [domain ...]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Output status of domain or domains. Can be one of:

* ``seen in named.conf, not parsed``,
* ``parsed successfully at <time>`` or
* ``error parsing at line ... at <time>``.

``bind-list-rejects``
~~~~~~~~~~~~~~~~~~~~~

Lists all zones that have problems, and what those problems are.

``bind-reload-now <domain>``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Reloads a zone from disk NOW, reporting back results.

``rediscover``
~~~~~~~~~~~~~~

Reread the BIND configuration file (``named.conf``). If parsing fails,
the old configuration remains in force and ``pdns_control`` reports the
error. Any newly discovered domains are read, discarded domains are
removed from memory.

``reload``
~~~~~~~~~~

All zones with a changed timestamp are reloaded at the next incoming
query for them.

.. _bind_performance:

Performance
-----------

The BIND backend does not benefit from the packet cache as it is fast
enough on its own. Furthermore, on most systems, there will be no
benefit in using multiple CPUs for the packetcache, so a noticeable
speedup can be attained by specifying
``distributor-threads=1`` in ``pdns.conf``.

Master/slave/native configuration
---------------------------------

Master
~~~~~~

Works as expected. At startup, no notification storm is performed as
this is generally not useful. Perhaps in the future the BIND backend
will attempt to store zone metadata in the zone, allowing it to
determine if a zone has changed its serial since the last time
notifications were sent out.

Changes which are discovered when reloading zones do lead to
notifications however.

Slave
~~~~~

Also works as expected. The BIND backend expects to be able to write to
a directory where a slave domain lives. The incoming zone is stored as
'zonename.RANDOM' and atomically renamed if it is retrieved
successfully, and parsed only then.

In the future, this may be improved so the old zone remains available
should parsing fail.

Native
~~~~~~

PowerDNS has the concept of "native" zones that have the
``type native;`` in the BIND configuration file. These zones are neither
a master (no notifies are sent) nor a slave zone (it will never be
AXFR'd in). This means that the replication mechanism for these zone is
not AXFR but out of band, e.g. using ``rsync``. Changes to native zones
are picked up in the same way as master and slave zones, see
:ref:`bind-operation`.

Native zones in the BIND backend are supported since version 4.1.0 of
the PowerDNS Authoritative Server.

.. note::
  Any zone with no ``type`` set (an error in BIND) is assumed to be native.
