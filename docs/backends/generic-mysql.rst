Generic MySQL/MariaDB  backend
==============================

* Native: Yes
* Primary: Yes
* Secondary: Yes
* Producer: Yes
* Consumer: Yes
* Autosecondary: Yes
* DNS Update: Yes
* DNSSEC: Yes (set ``gmysql-dnssec``)
* Disabled data: Yes
* Comments: Yes
* API: Read-Write
* Multiple instances: yes
* Zone caching: Yes
* Module name: gmysql
* Launch name: ``gmysql``

.. warning::
  If using MySQL with 'slave' support enabled in PowerDNS you
  **must** run MySQL with a table engine that supports transactions. In
  practice, great results are achieved with the 'InnoDB' tables. PowerDNS
  will silently function with non-transaction aware MySQLs but at one
  point this is going to harm your database, for example when an incoming
  zone transfer fails.

.. warning::
  While it is possible to run the Generic MySQL/MariaDB backend on top of MySQL/MariaDB 
  views, we have received several reports of this causing performance
  problems and memory leaks.  Please know that when reporting problems when
  running PowerDNS on top of a modified schema, our open source support
  offering requires you to reproduce your problem on an unmodified schema without
  views.

The default schema is included at the bottom of this page.
:ref:`migration-zone2sql` with the ``--gmysql`` flag also
assumes this layout is in place. For full migration notes, please see
:doc:`../migration`. This schema contains all elements needed
for master, slave and superslave operation.

When using the InnoDB storage engine, we suggest adding foreign key
constraints to the tables in order to automate deletion of records, key
material, and other information upon deletion of a domain from the
domains table. The following SQL does the job:

.. literalinclude:: ../../modules/gmysqlbackend/enable-foreign-keys.mysql.sql
   :language: SQL

Using MySQL/MariaDB replication
-------------------------------

To support ``NATIVE`` domains, the ``binlog_format`` for the MySQL/MariaDB
replication **must** be set to ``MIXED`` or ``ROW`` to prevent
differences in data between replicated servers. See `"Setting
The Binary Log
Format" <http://dev.mysql.com/doc/refman/5.7/en/binary-log-setting.html>`__
and `"Binary Log Formats" <https://mariadb.com/kb/en/binary-log-formats/>`__
for more information.

Otherwise, you will probably see:

::

  Cannot execute statement: impossible to write to binary log since BINLOG_FORMAT = STATEMENT and at least one table uses a storage engine limited to row-based logging.
  InnoDB is limited to row-logging when transaction isolation level is READ COMMITTED or READ UNCOMMITTED.

Settings
--------

.. _setting-gmysql-host:

``gmysql-host``
^^^^^^^^^^^^^^^

Host (ip address) to connect to. Mutually exclusive with :ref:`setting-gmysql-socket`.

.. warning::
  When specified as a hostname a chicken/egg situation might
  arise where the database is needed to resolve the IP address of the
  database. It is best to supply an IP address of the database here.

.. _setting-gmysql-port:

``gmysql-port``
^^^^^^^^^^^^^^^

The port to connect to on :ref:`setting-gmysql-host`. Default: 3306.

.. _setting-gmysql-socket:

``gmysql-socket``
^^^^^^^^^^^^^^^^^

Connect to the UNIX socket at this path. Mutually exclusive with :ref:`setting-gmysql-host`.

.. _setting-gmysql-dbname:

``gmysql-dbname``
^^^^^^^^^^^^^^^^^

Name of the database to connect to. Default: "powerdns".

.. _setting-gmysql-user:

``gmysql-user``
^^^^^^^^^^^^^^^

User to connect as. Default: "powerdns".

.. _setting-gmysql-group:

``gmysql-group``
^^^^^^^^^^^^^^^^

Group to connect as. Default: "client".

.. _setting-gmysql-password:

``gmysql-password``
^^^^^^^^^^^^^^^^^^^

The password to for :ref:`setting-gmysql-user`.

.. _setting-gmysql-dnssec:

``gmysql-dnssec``
^^^^^^^^^^^^^^^^^

Enable DNSSEC processing for this backend. Default: no.

.. _setting-gmysql-innodb-read-committed:

``gmysql-innodb-read-committed``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use the InnoDB READ-COMMITTED transaction isolation level. Default: yes.

.. _setting-gmysql-ssl:

``gmysql-ssl``
^^^^^^^^^^^^^^^^^^

.. deprecated:: 5.0.0

Before 5.0.0: Send the CLIENT_SSL capability flag to the server. SSL support is announced by the server via CLIENT_SSL and is enabled if the client returns the same capability. Default: no.

5.0.0 and up: this option does nothing. Use ``gmysql-group`` and put your TLS settings in ``my.cnf``.

.. _setting-gmysql-timeout:

``gmysql-timeout``
^^^^^^^^^^^^^^^^^^

The timeout in seconds for each attempt to read from, or write to the
server. A value of 0 will disable the timeout. Default: 10

.. _setting-gmysql-thread-cleanup:

``gmysql-thread-cleanup``
^^^^^^^^^^^^^^^^^^^^^^^^^

Older versions (such as those shipped on RHEL 7) of the MySQL/MariaDB client libraries leak memory unless applications explicitly report the end of each thread to the library. Enabling ``gmysql-thread-cleanup`` tells PowerDNS to call ``mysql_thread_end()`` whenever a thread ends.

Only enable this if you are certain you need to. For more discussion, see https://github.com/PowerDNS/pdns/issues/6231.

Default Schema
--------------

This is the 4.7 schema.

.. literalinclude:: ../../modules/gmysqlbackend/schema.mysql.sql
