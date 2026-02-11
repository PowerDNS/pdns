LMDB backend
============

* Native: Yes
* Primary: Yes
* Secondary: Yes
* Producer: Yes
* Consumer: Yes
* Autosecondary: No
* DNS Update: since version 5.0.0
* DNSSEC: Yes
* Disabled data: Yes
* Comments: No
* Search: since version 5.0.0
* Views: Yes
* API: Read-Write
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

Path to the LMDB file (e.g. */var/lib/powerdns/pdns.lmdb*)

.. warning::
  On systemd systems,
  When running PowerDNS via the provided systemd service file, `ProtectSystem <https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=>`_ is set to ``full``, this means PowerDNS is unable to write to e.g. ``/etc`` and ``/home``, possibly being unable to write to the LMDB database.

.. _setting-lmdb-shards:

``lmdb-shards``
^^^^^^^^^^^^^^^^^

Records database will be split into this number of shards e.g. lmdb-shards=64.
Default is 2 on 32 bits systems, and 64 on 64 bits systems.

.. _setting-lmdb-sync-mode:

``lmdb-sync-mode``
^^^^^^^^^^^^^^^^^^

  .. versionchanged:: 4.9.0

  ``mapasync`` choice removed

Synchronisation mode: one of sync, nosync, nometasync (default: sync).

``sync`` (default since 4.9.0)
  LMDB synchronous mode. Safest option, but also slightly slower. Can also be enabled with ``lmdb-sync-mode=``

``nosync``
  don't flush systems buffers to disk when committing a transaction.
  This means a system crash can corrupt the database or lose the last transactions if buffers are not yet flushed to disk.

``nometasync``
  flush system buffers to disk only once per transaction, omit the metadata flush. This maintains database integrity, but can potentially lose the last committed transaction if the operating system crashes.

``mapasync`` (default before 4.9.0)
  Due to a bug before version 4.9.0, this actually gave ``sync`` behaviour.
  The ``mapasync`` choice has been removed in version 4.9.0.

.. _setting-lmdb-schema-version:

``lmdb-schema-version``
^^^^^^^^^^^^^^^^^^^^^^^

Determines the maximum schema version LMDB is allowed to upgrade to. If the on disk LMDB database has a lower version than the current version of the LMDB schema the backend will not start, unless this setting allows it to upgrade the schema. If the version of the DB is already the same as the current schema version this setting is not checked and the backend will start normally.

The default value for this setting is the highest supported schema version for the version of PowerDNS you are starting. If you want to prevent automatic schema upgrades, explicitly set this setting to the current default before upgrading PowerDNS.

================  ===================
PowerDNS Version  LMDB Schema version
================  ===================
4.2.x             1
4.3.x             2
4.4.x to 4.6.x    3
4.7.x and up      4
4.8.x and up      5
5.0.x and up      6
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

  .. versionchanged:: 5.1.0

From version 5.1.0 onwards, this settings only applies to the main database
file; shards use :ref:`settings-lmdb-shards-map-size` instead.

.. _settings-lmdb-shards-map-size:

``lmdb-shards-map-size``
^^^^^^^^^^^^^^^^^^^^^^^^

  .. versionadded:: 5.1.0

Size, in megabytes, of each LMDB shard database.
This number can be increased later, but never decreased.
If set to zero (which is its default value), the same value as
:ref:`settings-lmdb-map-size` will be used.

.. _settings-lmdb-flag-deleted:

``lmdb-flag-deleted``
^^^^^^^^^^^^^^^^^^^^^

  .. versionadded:: 4.8.0

-  Boolean
-  Default: no

Instead of deleting items from the database, flag them as deleted in the item's `Lightning Stream <https://doc.powerdns.com/lightningstream>`_ header.
Only enable this if you are using Lightning Stream.

.. _setting-lmdb-write-notification-update:

``lmdb-write-notification-update``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  .. versionadded:: 5.0.1

-  Boolean
-  Default: yes

Always update the domains table in the database when the last notification
or the freshness check timestamp are modified.
If disabled, these timestamps will only be written back to the database when
other changes to the domain (such as accounts) occur.
This setting is also available in version 4.9.9.

**Warning**: Running with this flag disabled will cause spurious notifications
to be sent upon startup, unless a ``flush`` command is sent using
:doc:`pdns_control <../manpages/pdns_control.1>` before stopping the
PowerDNS Authoritative Server.

``lmdb-split-domains-table``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  .. versionadded:: 5.1.0

-  Boolean
-  Default: no

Split the domains table in two, with the last notification timestamp and
last freshness check timestamp in a separate table.
This lowers the I/O bandwidth requirements on setups with many zones.

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
Also, it is not possible to directly query the LMDB DB, so recommendation is to use either the API, or :doc:`pdnsutil <../manpages/pdnsutil.1>`.
