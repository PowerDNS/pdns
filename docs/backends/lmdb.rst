LMDB backend
============

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: No
* Case: All lower
* DNSSEC: Yes
* Disabled data: Yes
* Comments: No
* Multiple instances: No
* Zone caching: Yes
* Module name: lmdb
* Launch name: ``lmdb``


.. warning::
  The LMDB backend is considered stable as of 4.4.0. Version 4.3.0 was stable but had an important `known bug <https://github.com/PowerDNS/pdns/issues/8012>`__, that affects anybody with big records such as long TXT content.

Enabling the backend
--------------------

When building PowerDNS yourself, append ``lmdb`` to ``--with-modules`` or ``--with-dynmodules``. It is expected that most pre-built packages contain this backend or be separately installable.


Settings
--------

.. _setting-lmdb-filename:

``lmdb-filename``
^^^^^^^^^^^^^^^^^

Path to the LMDB file (e.g. */var/spool/powerdns/pdns.lmdb*)

.. warning::
  On systemd systems,
  When running PowerDNS via the provided systemd service file, `ProtectSystem <http://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=>`_ is set to ``full``, this means PowerDNS is unable to write to e.g. ``/etc`` and ``/home``, possibly being unable to write to the LMDB database.

.. _setting-lmdb-shards:

``lmdb-shards``
^^^^^^^^^^^^^^^^^

Records database will be split into this number of shards e.g. lmdb-shards=64
Default is 2 on 32 bits systems, and 64 on 64 bits systems.

.. _setting-lmdb-sync-mode:

``lmdb-sync-mode``
^^^^^^^^^^^^^^^^^^

* Synchronisation mode: sync, nosync, nometasync, mapasync
* Default: mapasync

``sync``
  LMDB synchronous mode. Safest option, but also slightly slower. Can  also be enabled with ``lmdb-sync-mode=``

``nosync``
  don't flush systems buffers to disk when committing a transaction.
  This means a system crash can corrupt the database or lose the last transactions if buffers are not yet flushed to disk.

``nometasync``
  flush system buffers to disk only once per transaction, omit the metadata flush. This maintains database integrity, but can potentially lose the last committed transaction if the operating system crashes.

``mapasync`` (default)
  Use asynchronous flushes to disk. As with nosync, a system crash can then corrupt the database or lose the last transactions.

.. _setting-lmdb-schema-version:

``lmdb-schema-version``
^^^^^^^^^^^^^^^^^^^^^^^

Determines the maximum schema version LMDB is allowed to upgrade to. If the on disk LMDB database has a lower version than the current version of the LMDB schema the backend will not start, unless this setting allows it to upgrade the schema. If the version of the DB is already the same as the current schema version this setting is not checked and the backend starts normally.

The default value for this setting is the highest supported schema version for the version of PowerDNS you are starting. if you want to prevent automatic schema upgrades, explicitly set this setting to the current default before upgrading PowerDNS.

================  ===================
PowerDNS Version  LMDB Schema version
================  ===================
4.2.x             1
4.3.x             2
4.4.x to 4.6.x    3
4.7.x and up      4
4.8.x and up      5
================  ===================

.. _settings-lmdb-random-ids:

``lmdb-random-ids``
^^^^^^^^^^^^^^^^^^^

  .. versionadded:: 4.7.0

-  Boolean
-  Default: no

Numeric IDs inside the database are generated randomly instead of sequentially.
If some external process is synchronising databases between systems, this will avoid conflicts when objects (domains, keys, etc.) get added.
This will also improve the detection of recreated zones for :doc:`Catalog Zones <../catalog>` producers.

.. _settings-lmdb-map-size:

``lmdb-map-size``
^^^^^^^^^^^^^^^^^

  .. versionadded:: 4.7.0

Size, in megabytes, of each LMDB database.
This number can be increased later, but never decreased.
Defaults to 100 on 32 bit systems, and 16000 on 64 bit systems.

.. _settings-lmdb-flag-deleted:

``lmdb-flag-deleted``
^^^^^^^^^^^^^^^^^^^^^

  .. versionadded:: 4.8.0

-  Boolean
-  Default: no

Instead of deleting items from the database, flag them as deleted in the item's `Lightning Stream <https://doc.powerdns.com/lightningstream>`_ header.
Only enable this if you are using Lightning Stream.

``lmdb-lightning-stream``
^^^^^^^^^^^^^^^^^^^^^^^^^

  .. versionadded:: 4.8.0

-  Boolean
-  Default: no

Run in Lightning Stream compatible mode. This:

* forces ``flag-deleted`` on
* forces ``random-ids`` on
* handles duplicate entries in databases that can result from domains being added on two Lightning Stream nodes at the same time
* aborts startup if ``shards`` is not set to ``1``

LMDB Structure
--------------

PowerDNS will create the database structure, no need to manually create the database schema.
Also, it is not possible to directly query the LMDB DB, so recommendation is to use either the API, or pdnsutil.
