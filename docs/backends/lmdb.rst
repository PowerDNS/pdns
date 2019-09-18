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
  The LMDB backend is EXPERIMENTAL, and as of 4.2.0, it has `known <https://github.com/PowerDNS/pdns/issues/8012>`__ `bugs <https://github.com/PowerDNS/pdns/issues/8134>`__. Be prepared for incompatible changes between minor releases in the 4.2.x branch, and while tracking our git master.

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


LMDB Structure
--------------

PowerDNS will create the database structure, no need to manually create the database schema.
Also, it is not possible to directly query the LMDB DB, so recommendation is to use either the API, or pdnsutil.
