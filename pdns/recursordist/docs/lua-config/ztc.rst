.. _ztc:

Zone to Cache
-------------

Zone to Cache is a function to load a zone into the Recursor cache periodically, or every time the Lua configuration is loaded, at startup and whenever ``rec_control reload-lua-config`` is issued.
This allows the Recursor to have an always hot cache for these zones.
The zone content to cache can be retrieved via zone transfer (AXFR format) or read from a zone file retrieved via http, https or a local file.

Example
^^^^^^^
To load the root zone from Internic into the recursor once at startup and when the Lua config is reloaded:

.. code-block:: Lua

     zoneToCache(".", "url", "https://www.internic.net/domain/root.zone", { refreshPeriod = 0 })

DNSSEC and ZONEMD validation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Starting with version 4.7.0, the Recursor will do validation of the zone retrieved.
Validation consists of two parts: ``DNSSEC`` and ``ZONEMD``.
``ZONEMD`` is described in :rfc:`8976`.

For the ``DNSSEC`` part, if the global :ref:`setting-yaml-dnssec.validation` setting is not ``off`` or ``process-no-validate`` and the `DS` record from the parent zone or trust anchor indicates the zone is ``DNSSEC`` signed, the recursor will validate the ``DNSKEY`` records of the zone.
If a ``ZONEMD`` record is present, it will also validate the ``ZONEMD`` record.
If no ``ZONEMD`` is present, the ``NSEC`` or ``NSEC3`` denial of the ``ZONEMD`` record will be validated.
Note that this is not a full validation of the signatures of all records.
The signatures of the remaining records will be verified on-demand once the records are inserted into the cache by the Zone to Cache function.

For the ``ZONEMD`` part, if the zone has a ``ZONEMD`` record with a matching serial number, supported digest algorithm and supported scheme, the digest of the zone will be verified.

For both parts failure of validation will prevent the downloaded zone contents from being inserted into the cache.
Absence of ``DNSSEC`` records is not considered a failure if the parent zone or negative trust anchor indicate the zone is ``Insecure``.
Absence of ``ZONEMD`` records is not considered a failure unless ``DNSSEC`` indicates ``ZONEMD`` records should be present.
This behaviour can be tuned with the ``zoneToCache`` specific `zonemd`_ and `dnssec`_ settings described below.


Configuration
^^^^^^^^^^^^^
.. function:: zoneToCache(zone, method, source [, settings ])

  .. versionadded:: 4.6.0
  .. versionadded:: 5.1.0 Alternative equivalent YAML setting: :ref:`setting-yaml-recordcache.zonetocaches`.

  Load a zone and put it into the Recursor cache periodically.

  :param str zone: The name of the zone to load
  :param str method: One of ``"axfr"``, ``"url"`` or ``"file"``
  :param str source: A string representing an IP address (when using the ``axfr`` method), URL (when using the ``url`` method) or path name (when using the ``file`` method)
  :param table settings: A table of settings, see below


Zone to Cache settings
^^^^^^^^^^^^^^^^^^^^^^

These options can be set in the ``settings`` of :func:`zoneToCache`.

timeout
~~~~~~~
The maximum time (in seconds) a retrieval using the ``axfr`` or ``url`` method may take.
Default is 20 seconds.

tsigname
~~~~~~~~
The name of the TSIG key to authenticate to the server and validate the zone content with when using the ``axfr`` method.
When this is set, `tsigalgo`_ and `tsigsecret`_ must also be set.

tsigalgo
~~~~~~~~
The name of the TSIG algorithm (like 'hmac-md5') used.

tsigsecret
~~~~~~~~~~
Base64 encoded TSIG secret.

refreshPeriod
~~~~~~~~~~~~~
An integer describing the interval (in seconds) to wait between retrievals.
A value of zero means the retrieval is done once at startup and on Lua configuration reload.
By default, the refresh value is 86400 (24 hours).

retryOnErrorPeriod
~~~~~~~~~~~~~~~~~~
An integer describing the interval (in seconds) to wait before retrying a failed transfer.
By default 60 is used.

maxReceivedMBytes
~~~~~~~~~~~~~~~~~
The maximum size in megabytes of an update via the ``axfr`` or ``url`` methods, to prevent resource exhaustion.
The default value of 0 means no restriction.

localAddress
~~~~~~~~~~~~
The source IP address to use when transferring using the ``axfr`` or ``url`` methods.
For the ``axfr`` method :ref:`setting-yaml-outgoing.source_address` is used by default.
The default used for ``url`` method is system dependent.

zonemd
~~~~~~

.. versionadded:: 4.7.0

A string, possible values: ``ignore``: ignore ZONEMD records, ``validate``: validate ``ZONEMD`` if present, ``require``: require valid ``ZONEMD`` record to be present.
Default ``validate``.


dnssec
~~~~~~

.. versionadded:: 4.7.0

A string, possible values: ``ignore``: do not do ``DNSSEC`` validation, ``validate``: validate ``DNSSEC`` records as described above but accept an ``Insecure`` (unsigned) zone, ``require``: require ``DNSSEC`` validation, as described above.
Default ``validate``.


