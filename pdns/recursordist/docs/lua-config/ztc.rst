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

Configuration
^^^^^^^^^^^^^
.. function:: zoneToCache(zone, method, source [, settings ])

  .. versionadded:: 4.6.0

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
When unset, :ref:`setting-query-local-address` is used.

