Bind zone file backend
======================

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: Experimental
* Autoserial: No
* DNSSEC: Yes
* Disabled data: No
* Comments: No
* API: Read-only
* Module name: bind
* Launch: ``bind``

The BindBackend started life as a demonstration of the versatility of
PowerDNS but quickly gained in importance when there appeared to be
demand for a Bind 'work-alike'.

The BindBackend parses a Bind-style ``named.conf`` and extracts
information about zones from it. It makes no attempt to honour other
configuration flags, which you should configure (when available) using
the PowerDNS native configuration.

**note**: Because this backend retrieves its configuration from a text file and not a database, the HTTP API is unable to process changes for this backend. This effectively makes the API read-only for zones hosted by the BIND backend.  

Configuration Parameters
------------------------

.. _setting-bind-config:

``bind-config``
~~~~~~~~~~~~~~~

Location of the Bind configuration file to parse.

PowerDNS does not support every directive supported by Bind.
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

How often to check for zone changes. See :ref:`bind-operation` section.

.. _setting-bind-dnssec-db:

``bind-dnssec-db``
~~~~~~~~~~~~~~~~~~

Filename to store and access our DNSSEC metadatabase, empty for none. To
slave DNSSEC-enabled domains (where the RRSIGS are in the AXFR), a
``bind-dnssec-db`` is required. This is because the
:ref:`metadata-presigned` domain metadata is set
during the zonetransfer.

.. warning::
   If this is left empty on slaves and a presigned zone is transferred,
   it will (silently) serve it without DNSSEC. This in turn results in
   serving the domain as bogus.

.. _setting-bind-hybrid:

``bind-hybrid``
~~~~~~~~~~~~~~~

Store DNSSEC keys and metadata storage in an other backend. See the
:ref:`dnssec-modes-hybrid-bind` documentation.

.. _setting-bind-ignore-broken-records:

``bind-ignore-broken-records``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Setting this option to ``yes`` makes PowerDNS ignore out of zone records
when loading zone files.

.. _bind-operation:

Operation
---------

On launch, the BindBackend first parses the ``named.conf`` to determine
which zones need to be loaded. These will then be parsed and made
available for serving, as they are parsed. So a ``named.conf`` with
100.000 zones may take 20 seconds to load, but after 10 seconds, 50.000
zones will already be available. While a domain is being loaded, it is
not yet available, to prevent incomplete answers.

Reloading is currently done only when a request for a zone comes in, and
then only after :ref:`setting-bind-check-interval`.
seconds have passed after the last check. If a change occurred, access
to the zone is disabled, the file is reloaded, access is restored, and
the question is answered. For regular zones, reloading is fast enough to
answer the question which lead to the reload within the DNS timeout.

If :ref:`setting-bind-check-interval` is specified as
zero, no checks will be performed until the ``pdns_control reload`` is
given.

pdns\_control commands
----------------------

``bind-add-zone <domain> <filename>``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add zone ``domain`` from ``filename`` to PowerDNS's bind backend. Zone
will be loaded at first request.

.. note::
  This does not add the zone to the :ref:`setting-bind-config` file.

``bind-domain-status <domain> [domain]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Output status of domain or domains. Can be one of
``seen in named.conf, not parsed``, ``parsed successfully at <time>`` or
``error parsing at line ... at <time>``.

``bind-list-rejects``
~~~~~~~~~~~~~~~~~~~~~

Lists all zones that have problems, and what those problems are.

``bind-reload-now <domain>``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Reloads a zone from disk NOW, reporting back results.

``rediscover``
~~~~~~~~~~~~~~

Reread the bind configuration file (``named.conf``). If parsing fails,
the old configuration remains in force and ``pdns_control`` reports the
error. Any newly discovered domains are read, discarded domains are
removed from memory.

``reload``
~~~~~~~~~~

All zones with a changed timestamp are reloaded at the next incoming
query for them.

Performance
-----------

The BindBackend does not benefit from the packet cache as it is fast
enough on its own. Furthermore, on most systems, there will be no
benefit in using multiple CPUs for the packetcache, so a noticeable
speedup can be attained by specifying
``distributor-threads=1`` in ``pdns.conf``.

Master/slave/native configuration
---------------------------------

Master
~~~~~~

Works as expected. At startup, no notification storm is performed as
this is generally not useful. Perhaps in the future the Bind Backend
will attempt to store zone metadata in the zone, allowing it to
determine if a zone has changed its serial since the last time
notifications were sent out.

Changes which are discovered when reloading zones do lead to
notifications however.

Slave
~~~~~

Also works as expected. The Bind backend expects to be able to write to
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

**note**: Any zone with no ``type`` set (an error in BIND) is assumed to
be native.
