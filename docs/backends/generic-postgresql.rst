Generic PostgreSQL backend
==========================

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: Yes
* Autoserial: No
* Case: All lower
* DNSSEC: Yes (set ``gpgsql-dnssec``)
* Disabled data: Yes
* Comments: Yes
* Module name: gpgsql
* Launch name: ``gpgsql``

This PostgreSQL backend is based on the :doc:`generic-sql`. The default setup conforms to the
schema at the bottom of this page, note that
:ref:`zone2sql <migration-zone2sql>` with the ``--gpgsql`` flag also
assumes this layout is in place.

This schema contains all elements needed for master, slave and
superslave operation. For full migration notes, please see
:doc:`Migration <../migration>` docs.

With PostgreSQL, you may have to run ``createdb pdns`` first and then
connect to that database with ``psql pdns``, and feed it the schema
above.

Settings
--------

.. _setting-gpgsql-host:

``gpgsql-host``
^^^^^^^^^^^^^^^

Host (ip address) to connect to. If ``pgsql-host`` begins with a slash,
it specifies Unix-domain communication rather than TCP/IP communication;
the value is the name of the directory in which the socket file is
stored. Default: not set.

.. warning::
  When specified as a hostname a chicken/egg situation might
  arise where the database is needed to resolve the IP address of the
  database. It is best to supply an IP address of the database here.

.. _setting-gpgsql-port:

``gpgsql-port``
^^^^^^^^^^^^^^^

The port to connect to on :ref:`setting-gpgsql-host`. Default: not set.

.. _setting-gpgsql-dbname:

``gpgsql-dbname``
^^^^^^^^^^^^^^^^^

Name of the database to connect to. Default: not set.

.. _setting-gpgsql-user:

``gpgsql-user``
^^^^^^^^^^^^^^^

User to connect as. Default: not set.

.. _setting-gpgsql-password:

``gpgsql-password``
^^^^^^^^^^^^^^^^^^^

The password to for :ref:`setting-gpgsql-user`. Default: not set.

.. _setting-gpgsql-dnssec:

``gpgsql-dnssec``
^^^^^^^^^^^^^^^^^

Enable DNSSEC processing for this backend. Default: no.

.. _setting-gpgsql-extra-connection-parameters:

``gpgsql-extra-connection-parameters``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Extra connection parameters to forward to postgres. If you want to pin a
specific certificate for the connection you should set this to
``sslmode=verify-full sslrootcert=<path-to-CA-cert>``. Accepted
parameters are documented `in the PostgreSQL
documentation <https://www.postgresql.org/docs/current/static/libpq-connect.html#LIBPQ-PARAMKEYWORDS>`__.
Default: "".

Default schema
--------------

This is the 4.2 schema. Please find `the 4.1 schema on GitHub <https://github.com/PowerDNS/pdns/blob/rel/auth-4.1.x/modules/gpgsqlbackend/schema.pgsql.sql>`_.

.. literalinclude:: ../../modules/gpgsqlbackend/schema.pgsql.sql
   :language: SQL
