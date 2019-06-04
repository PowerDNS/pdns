Generic SQLite 3 backend
========================

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: Yes
* DNSSEC: Yes
* Disabled data: Yes
* Comments: Yes
* Module name: gsqlite3
* Launch name: ``gsqlite3``

.. warning::
  When importing large amounts of data, be sure to run
  ``analyze;`` afterwards as SQLite3 has a tendency to use very sub-optimal
  indexes otherwise.

This backend retrieves all data from a SQLite database, which is an
RDBMS that's embedded into the application itself, so you won't need to
be running a separate server process. It also reduces overhead, and
simplifies installation. At `www.sqlite.org <http://www.sqlite.org>`__
you can find more information about SQLite.

As this is a generic backend, built on top of the gSql framework, you
can specify all queries as documented in :ref:`Generic SQL Backends <generic-sql-queries>`.

SQLite exists in two incompatible versions, PowerDNS only supports
version 3. To launch the backend, put ``launch=gsqlite3`` in the
configuration.

Setting up the database
------------------------

Before you can use this backend you first have to set it up and fill it
with data. The default setup conforms to the following schema in 4.2.
If you have not upgraded to 4.2, please use `the 4.1 schema on GitHub <https://github.com/PowerDNS/pdns/blob/rel/auth-4.1.x/modules/gsqlite3backend/schema.sqlite3.sql>`_.

.. literalinclude:: ../../modules/gsqlite3backend/schema.sqlite3.sql

This schema contains all elements needed for master, slave and
superslave operation.

.. warning::
  It is not possible to replace the sqlite3 database file while PowerDNS is
  running. Specifically, using ``rsync`` to distribute sqlite3 databases
  does not work without stopping PowerDNS first and restarting it after the
  change.

After you have created the database you probably want to fill it with
data. If you have a BIND zone file it's as easy as:
``zone2sql --named-conf=/path/to/named.conf --gsqlite | sqlite3 powerdns.sqlite3``,
but you can also use AXFR (or insert data manually).

To communicate with a SQLite database, use the ``sqlite3`` program, and
feed it SQL.

Configuration Parameters
------------------------

These are the configuration file parameters that are available for the
gsqlite3 backend.

.. _setting-gsqlite3-database:

``gsqlite3-database``
~~~~~~~~~~~~~~~~~~~~~

Path to the SQLite3 database.

.. _setting-gsqlite3-pragma-journal-mode:

``gsqlite3-pragma-journal-mode``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SQLite3 journal mode to set. The default is WAL. Set to empty to leave the journal mode alone.

.. _setting-gsqlite3-pragma-synchronous:

``gsqlite3-pragma-synchronous``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set this to 0 for blazing speed.

.. _setting-gsqlite3-pragma-foreign-keys:

``gsqlite3-pragma-foreign-keys``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enable foreign key constraints.

.. _setting-gsqlite3-dnssec:

``gsqlite3-dnssec``
~~~~~~~~~~~~~~~~~~~

Enable DNSSEC processing.

Using the SQLite backend
------------------------

The last thing you need to do is telling PowerDNS to use the SQLite
backend in pdns.conf:

.. code-block:: ini

    launch=gsqlite3
    gsqlite3-database=<path to your SQLite database>

Then you can start PowerDNS and it should notify you that a connection
to the database was made.

Compiling the SQLite backend
----------------------------

Before you can begin compiling PowerDNS with the SQLite backend you need
to have the SQLite utility and library installed on your system. You can
download these from http://www.sqlite.org/download.html, or you can use
packages (if your distribution provides those).

When you've installed the library you can use:
``./configure --with-modules="gsqlite3"`` to configure PowerDNS to use
the SQLite backend. Compilation can then proceed as usual.

SQLite is included in most PowerDNS binary releases.
