Generic PostgreSQL backend
==========================

* Native: Yes
* Primary: Yes
* Secondary: Yes
* Producer: Yes
* Consumer: Yes
* Autosecondary: Yes
* DNS Update: Yes
* DNSSEC: Yes (set ``gpgsql-dnssec``)
* Disabled data: Yes
* Comments: Yes
* Search: Yes
* Views: No
* API: Read-Write
* Multiple instances: yes
* Zone caching: Yes
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
  When specified as a hostname, a chicken/egg situation might
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

The password for :ref:`setting-gpgsql-user`. Default: not set.

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

.. _setting-gpgsql-prepared-statements:

``gpgsql-prepared-statements``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Prepare statements for better performance, instead of sending parameterized queries.
Might not work with connection poolers.
Default: yes.

.. versionadded:: 4.4.0

Default schema
--------------

This is the 4.7 schema.

.. literalinclude:: ../../modules/gpgsqlbackend/schema.pgsql.sql
   :language: SQL

CockroachDB
-----------

`CockroachDB <https://www.cockroachlabs.com/docs/stable/architecture/overview.html>`__ is a highly available, resilient database that focuses on scaling and consistency. Specifically: it offers a PostgreSQL like database interface,
which means that most tools that talk the PostgreSQL protocol can use it.

A few changes are needed on top of the generic PostgreSQL settings. CockroachDB does not natively support the range operators that some PowerDNS database queries use,
and care must be taken that table index columns do not exceed the internal maximum integer size that PowerDNS uses.

Schema differences
^^^^^^^^^^^^^^^^^^

Given the normal pgsql schema, change the following:

1. Add explicit SEQUENCEs for all SERIAL columns:

.. code-block:: SQL

  CREATE SEQUENCE domain_id MAXVALUE 2147483648;
  CREATE SEQUENCE record_id MAXVALUE 2147483648;
  CREATE SEQUENCE comment_id MAXVALUE 2147483648;
  CREATE SEQUENCE meta_id MAXVALUE 2147483648;
  CREATE SEQUENCE key_id MAXVALUE 2147483648;
  CREATE SEQUENCE tsig_id MAXVALUE 2147483648;

2. Change all SERIAL / BIGSERIAL columns to use the SEQUENCEs. For instance, change

.. code-block:: SQL

  CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
  )

to

.. code-block:: SQL

  CREATE TABLE domains (
    id INT DEFAULT nextval('domain_id') PRIMARY KEY,
  );


3. Do **not** add the following index to the records table, the text_pattern_ops operator class is not supported:

.. code-block:: SQL

  CREATE INDEX recordorder ON records (domain_id, ordername text_pattern_ops);


Configuration changes
^^^^^^^^^^^^^^^^^^^^^

Four queries must be overridden in the PowerDNS config, because by default they use a range operator that is not supported. These modified queries are actually
taken from the generic MySQL backend, and modified for syntax:

.. code-block:: ini

  gpgsql-get-order-first-query=select ordername from records where domain_id = $1 and disabled = false and ordername is not null order by 1 asc limit 1
  gpgsql-get-order-before-query=select ordername, name from records where ordername <= $1 and domain_id = $2 and disabled = false and ordername is not null order by 1 desc limit 1
  gpgsql-get-order-after-query=select ordername from records where ordername > $1 and domain_id = $2 and disabled = false and ordername is not null order by 1 asc limit 1
  gpgsql-get-order-last-query=select ordername, name from records where ordername != '' and domain_id = $1 and disabled = false and ordername is not null order by 1 desc limit 1

References
^^^^^^^^^^

See `this GitHub issue <https://github.com/PowerDNS/pdns/issues/5375#issuecomment-644771800>`__ for the original tests and a full working schema.
