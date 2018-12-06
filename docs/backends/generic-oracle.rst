Generic Oracle backend
======================

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: Yes
* Autoserial: No
* Case: All lower
* DNSSEC: Yes (set ``goracle-dnssec``)
* Disabled data: Yes
* Comments: Yes
* Module name: goracle
* Launch name: ``goracle``

The Generic Oracle Backend is a :doc:`generic-sql`. The default setup conforms to the
following schema, which you should add to an Oracle database. You may
need or want to add ``namespace`` statements.

Below, you will find the schema for 4.2. If you are using 4.1 or earlier, please find `the 4.1 schema on GitHub <https://github.com/PowerDNS/pdns/blob/rel/auth-4.1.x/modules/goraclebackend/schema.goracle.sql>`_.

.. literalinclude:: ../../modules/goraclebackend/schema.goracle.sql

This schema contains all elements needed for master, slave and
superslave operation.

Inserting records is a bit different compared to MySQL and PostgreSQL,
you should use:

.. code-block:: SQL

    INSERT INTO domains (id,name,type) VALUES (domains_id_sequence.nextval, 'example.net', 'NATIVE');

Settings
--------

.. _setting-goracle-tnsname:

``goracle-tnsname``
^^^^^^^^^^^^^^^^^^^

Which TNSNAME the Generic Oracle Backend should be connecting to. There
are no ``goracle-dbname``, ``goracle-host`` or ``goracle-port``
settings, their equivalent is in ``/etc/tnsnames.ora``.

.. _setting-goracle-dnssec:

``goracle-dnssec``
^^^^^^^^^^^^^^^^^^

Enable DNSSEC processing for this backend. Default=no.

Caveats
-------

Password Expiry
^^^^^^^^^^^^^^^

When your password is about to expire, and logging into oracle warns
about this, the Generic Oracle backend can no longer login, and will a
OCILogin2 warning.

To work around this, either update the password in time or remove
expiration from the account used.
