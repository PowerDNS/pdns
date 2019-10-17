Migrating to PowerDNS
=====================

Before migrating to PowerDNS a few things should be considered.

PowerDNS does not operate as a :ref:`slave-operation` or
:ref:`master-operation` server with all backends. The :doc:`Generic SQL <backends/generic-sql>` and
:doc:`BIND <backends/bind>` backends have the ability to act as master or
slave. See the :doc:`table of backends <backends/index>`
which other backends support these modes.

Using AXFR to a Slave-Capable Backend
-------------------------------------

The easiest way to migrate all your zones from your old infrastructure
to PowerDNS is to add all your domains as a slave domain with your
current master as the master, wait for the zones to be transferred and
change the zones to master. Make sure :ref:`setting-slave` is set to "yes"
in your pdns.conf.

To A Generic SQL Backend
~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
  This assumes the schema provided with PowerDNS is in place

In order to migrate to a Generic SQL backend, add all your domains to
the 'domains' table with the IP of your current master. On your current
master, make sure that this master allows AXFRs to this new slave.

.. code-block:: SQL

    INSERT INTO domains (name,type,master) VALUES ('example.net', 'SLAVE', '198.51.100.101');

Then start PowerDNS and wait for all the zones to be transferred. If
this server is the new :ref:`master <master-operation>`, change the type of
domain in the database:

.. code-block:: SQL

    UPDATE domains set type='MASTER' where type='SLAVE';

And set :ref:`setting-master` to "yes" in your pdns.conf
and restart PowerDNS.

Or, if you want to use :ref:`native <native-operation>`:

.. code-block:: SQL

    UPDATE domains set type='NATIVE' where type='SLAVE';

To the BIND backend
~~~~~~~~~~~~~~~~~~~

Create a named.conf with all the domains as slave domains, e.g.:

::

    zone "example.net" in {
      type slave;
      file "/var/lib/powerdns/zones/example.net.zone";
      masters {
        198.51.100.101;
      };
    };

Make sure the directory is writable for the ``pdns_server`` process and
that :ref:`setting-bind-config` parameter
references this file. Now start PowerDNS and wait untill all zones are
transferred. Now you can change the zone type to master:

::

    zone "example.net" in {
      type master;
      file "/var/lib/powerdns/zones/example.net.zone";
    };

Don't forget to enable :ref:`setting-master` in your
pdns.conf and restart, or if this setting was already set, use
``pdns_control rediscover`` to load these zones as master zones.

From zonefiles to PowerDNS
--------------------------

Using the BIND backend
~~~~~~~~~~~~~~~~~~~~~~

To use the BIND backend, set ``launch=bind`` and
``bind-config=/path/to/named.conf`` in your ``pdns.conf``. Note that
PowerDNS will not honor any options from named.conf, it will only use
the ``zone`` statements. See the :doc:`BIND backend <backends/bind>`
documentation for more information.

To a Generic SQL backend
~~~~~~~~~~~~~~~~~~~~~~~~

There are several methods to migrate to a :doc:`Generic SQL <backends/generic-sql>` backend.

.. _migration-zone2sql:

Using ``zone2sql``
^^^^^^^^^^^^^^^^^^

To migrate, the ``zone2sql`` tool is provided. This tool parses a BIND
``named.conf`` file and zone files and outputs SQL on standard out,
which can then be fed to your database. It understands the BIND master
file extension ``$GENERATE`` and will also honour ``$ORIGIN`` and
``$TTL``.

For backends supporting slave operation, there is also an option to keep
slave zones as slaves, and not convert them to native operation.

``zone2sql`` can generate SQL for nearly all the Generic SQL backends.
See `its manpage <manpages/zone2sql.1>` for more information.

An example call to ``zone2sql`` could be:

.. code-block:: shell

    zone2sql --named-conf=/path/to/named.conf --gmysql | mysql -u pdns -p pdns-db

This will generate the SQL statements for the :doc:`Generic MySQL <backends/generic-mysql>` and pipe them into the pdns-db
database in MySQL.

Using ``pdnsutil load-zone``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The :doc:`pdnsutil <manpages/pdnsutil.1>` tool has a
``load-zone`` command that ingests a zone file and imports it into the
first backend that is capable of hosting it.

To import, configure the backend and run
``pdnsutil load-zone example.com /tmp/example.com.zone`` to import
the ``example.com`` domain from the ``/tmp/example.com.zone`` file. The
zone is imported atomically (i.e. it is fully imported, or not) and any
existing records for that zone are overwritten. This include the SOA record too.

.. _b2b-migrate:

Migrating Data from one Backend to Another Backend
--------------------------------------------------

.. note::
  This is experimental feature.

Syntax: ``pdnsutil b2b-migrate OLD NEW``

This tool lets you migrate data from one backend to another, it moves
all data, including zones, metadata and crypto keys (if present). Some
example use cases are moving from BIND-style zonefiles to SQL based, or
other way around.

Prerequisites
~~~~~~~~~~~~~

-  Target backend must support same features as source from set of
   domains, zones, metadata, DNSSEC and TSIG. See :doc:`Backend
   Capabilities <backends/index>`
-  There must be no data in the target backend, otherwise the migration
   will fail. This is checked.

You can perform live upgrade with this tool, provided you follow the
procedure.

Moving from source to target
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Take backups of everything.
-  Configure both backends to pdns.conf, if you have source configured,
   you can just add target backend. **DO NOT RESTART AUTH SERVER BEFORE
   YOU HAVE FINISHED**
-  Then run ``pdnsutil b2b-migrate old new``, the old and new being
   configuration prefixes in pdns.conf. If something goes wrong, make
   sure you properly clear **ALL** data from target backend before
   retrying.
-  Remove (or comment out) old backend from pdns.conf, and run
   ``pdnsutil rectify-all-zones`` and ``pdnsutil check-all-zones`` to
   make sure everything is OK.
-  If everything is OK, then go ahead to restart your PowerDNS service.
   Check logs to make sure everything went ok.
