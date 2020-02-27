LMDB backend
============

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: No
* Case: All lower
* DNSSEC: Yes 
* Disabled data: No
* Comments: No
* Module name: lmdb
* Launch name: ``lmdb``


.. warning::
  The LMDB backend is considered stable as of 4.3.0, but it has one important `known bug <https://github.com/PowerDNS/pdns/issues/8012>`__, that affects anybody with big records such as long TXT content. Because of that bug, we suspect production deployment is still limited, which means some bugs may not have been found yet. We do not plan to do any breaking changes in the 4.3.x time frame; this means that the 'long content' bug will hopefully be fixed in 4.4.0.

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

Synchronisation mode: sync, nosync, nometasync, mapasync
Default: mapasync

* ``sync``: LMDB synchronous mode. Safest option, but also slightly slower. Can  also be enabled with ``lmdb-sync-mode=`` 
* ``nosync``: don't flush systems buffers to disk when committing a transation.
  This means a system crash can corrupt the database or lose the last transactions if buffers are not yet flushed to disk.
* ``nometasync``: flush system buffers to disk only once per transaction, omit the metadata flush. This maintains database integrity, but can potentially lose the last committed transaction if the operating system crashes.
* ``mapasync``: (default). Use asynchronous flushes to disk. As with nosync, a system crash can then corrupt the database or lose the last transactions.

.. _setting-lmdb-schema-version:

``lmdb-schema-version``
^^^^^^^^^^^^^^^^^^^^^^^

Determines the maximum schema version LMDB is allowed to upgrade to. If the on disk LMDB database has a lower version that the current version of the LMDB schema the backend will not start, unless this setting allows it to upgrade the schema. If the version of the DB is already the same as the current schema version this setting is not checked and the backend starts normally.

The default value for this setting is the highest supported schema version for the version of PowerDNS you are starting. if you want to prevent automatic schema upgrades, explicitly set this setting to the current default before upgrading PowerDNS.

LMDB Structure
--------------

PowerDNS will create the database structure, no need to manually create the database schema.
Also, it is not possible to directly query the LMDB DB, so recommendation is to use either the API, or pdnsutil.
