MyDNS Backend
=============

* Native: Yes
* Master: No
* Slave: No
* Superslave: No
* Autoserial: No
* Case: Depends
* DNSSEC: No
* Disabled data: No
* Comments: No
* Module name: mydns
* Launch name: ``mydns``

The MyDNS backend makes PowerDNS a drop-in replacement for the
`MyDNS <http://mydns.bboy.net/>`__ nameserver, as it uses the same
database schema.

Configuration Parameters
------------------------

.. _setting-mydns-host:

``mydns-host``
~~~~~~~~~~~~~~

Database host to connect to.

.. _setting-mydns-port:

``mydns-port``
~~~~~~~~~~~~~~

Port on the database server to connect to.

.. _setting-mydns-dbname:

``mydns-dbname``
~~~~~~~~~~~~~~~~

Name of the database to connect to, "mydns" by default.

.. _setting-mydns-user:

``mydns-user``
~~~~~~~~~~~~~~

User for the database, "powerdns" by default.

.. _setting-mydns-password:

``mydns-password``
~~~~~~~~~~~~~~~~~~

The user password.

.. _setting-mydns-socket:

``mydns-socket``
~~~~~~~~~~~~~~~~

Unix socket to connect to the database.

.. _setting-mydns-rr-table:

``mydns-rr-table``
~~~~~~~~~~~~~~~~~~

Name of the resource record table in the database, "rr" by default.

.. _setting-mydns-soa-table:

``mydns-soa-table``
~~~~~~~~~~~~~~~~~~~

Name of the SOA table in the database, "soa" by default.

.. _setting-mydns-soa-where:

``mydns-soa-where``
~~~~~~~~~~~~~~~~~~~

Additional WHERE clause for SOA, default is "1 = 1".

.. _setting-mydns-rr-where:

``mydns-rr-where``
~~~~~~~~~~~~~~~~~~

Additional WHERE clause for resource records, default is "1 = 1".

.. _setting-mydns-soa-active:

``mydns-soa-active``
~~~~~~~~~~~~~~~~~~~~

Use the active column in the SOA table, "yes" by default.

.. _setting-mydns-rr-active:

``mydns-rr-active``
~~~~~~~~~~~~~~~~~~~

Use the active column in the resource record table, "yes" by default.

.. _setting-mydns-use-minimal-ttl:

``mydns-use-minimal-ttl``
~~~~~~~~~~~~~~~~~~~~~~~~~

Setting this to 'yes' will make the backend behave like MyDNS on the TTL
values. Setting it to 'no' will make it ignore the minimal-ttl of the
zone. The default is "yes".

Migrating from MyDNS to another SQL backend
-------------------------------------------
To use one of the :doc:`generic SQL backend <generic-sql>`, like the :doc:`Postgresql <generic-postgresql>` or :doc:`MySQL <generic-mysql>` backends, the data can be migratedusing the :ref:`Backend to Backend <b2b-migrate>` migration guide.
