Oracle backend
==============

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: Yes
* Autoserial: No
* DNSSEC: Yes
* Comments: No
* Module name: oracle
* Launch name: ``oracle``

This is the Oracle Database backend with easily configurable SQL statements, allowing you to graft

.. warning::
  The Oracle backends depend on non-free software that requires significant
  resources from us to support. Consequently, we can not provide free
  support to users of this backend. Before deploying PowerDNS with an Oracle
  database, please head to `our commercial support page
  <https://www.powerdns.com/support.html>`_.

PowerDNS functionality onto any Oracle database of your choosing.

The Oracle backend is difficult, and possibly illegal, to distribute in
binary form. To use it, you will probably need to compile PowerDNS from
source. OCI headers are expected in ``$ORACLE_HOME/rdbms/public``, and
OCI libraries in ``$ORACLE_HOME/lib``. That is where they should be with
a working installation of the full Oracle Database client. Oracle
InstantClient should work as well, but you will need to make the
libraries and headers available in appropriate paths.

This backend uses two kinds of database connections. First, it opens a
session pool. Connections from this pool are used only for queries
reading DNS data from the database. Second, it opens normal (non-pooled)
connections on demand for any kind of write access. The reason for this
split is to allow redundancy by replication. Each DNS frontend server
can have a local read-only replicated instance of your database. Open
the session pool to the local replicated copy, and all data will be
available with high performance, even if the main database goes down.
The writing connections should go directly to the main database.

Of course, if you do not require this kind of redundancy, or want to
avoid the substantial Oracle Database licensing costs, all connections
can just go to the same database with the same credentials. Also, the
write connections should be entirely unnecessary if you do not plan to
use either master or slave mode.

Configuration Parameters
------------------------

.. _setting-oracle-pool:

``oracle-pool-database``, ``oracle-pool-username``, ``oracle-pool-password``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The database to use for read access. OracleBackend will try to create a
session pool, so make sure this database user has the necessary
permissions. If your connection requires environment variables to be
set, e.g. ``ORACLE_HOME``, ``NLS_LANG``, or ``LD_LIBRARY_PATH``, make
sure these are set when PowerDNS runs. ``/etc/default/pdns`` might help.

.. _setting-oracle-master:

``oracle-master-database``, ``oracle-master-username``, ``oracle-master-password``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The database to use for write access. These are normal connections, not
a session pool. The backend may open more than one at a time.

.. _setting-oracle-session:

``oracle-session-min``, ``oracle-session-max``, ``oracle-session-inc``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Parameters for the connection pool underlying the session pool. OCI will
open ``session-min`` connections at startup, and open more connections
as needed, ``session-inc`` at a time, until ``session-max`` connections
are open.

.. _setting-oracle-nameserver-name:

``oracle-nameserver-name``
~~~~~~~~~~~~~~~~~~~~~~~~~~

This can be set to an arbitrary string that will be made available in
the optional bind variable ``:nsname`` for all SQL statements. You can
use this to run multiple PowerDNS instances off the same database, while
serving different zones.

There are many more options that are used to define the different SQL
statements. These will be discussed after the reference database schema
has been explained.

The Database Schema
-------------------

You can find an example database schema in ``schema.sql`` in the
PowerDNS source distribution. It is intended more as a starting point to
come up with a schema that works well for your organisation, than as
something you should run as it is. As long as the semantics of the SQL
statements still work out, you can store your DNS data any way you like.

You should read this while having ``schema.sql`` to hand. Columns will
not be specifically explained where their meaning is obvious.

.. note::
  All FQDNs should be specified in lower case and without a
  trailing dot. Where things are lexicographically compared or sorted,
  make sure a sane ordering is used.
  ``'NLS_LANG=AMERICAN_AMERICA.AL32UTF8'`` should generally work well
  enough; when in doubt, enforce a plain ordering with
  ``"NLSSORT(value, 'NLS_SORT = BINARY')"``.

Zones Table
~~~~~~~~~~~

This table lists the zones for which PowerDNS is supposed to be an
authoritative nameserver, plus a small amount of information related to
master/slave mode.

name
^^^^

The FQDN of the zone apex, e.g. 'example.com'.

type
^^^^

Describes how PowerDNS should host the zone. Valid values are 'NATIVE',
'MASTER', and 'SLAVE'. PowerDNS acts as an authoritative nameserver for
the zone in all modes. In slave mode, it will additionally attempt to
acquire the zone's content from a master server. In master mode, it will
additionally send 'NOTIFY' packets to other nameservers for the zone
when its content changes.

**Tip**: There is a global setting to make PowerDNS send 'NOTIFY'
packets in slave mode.

last\_check
^^^^^^^^^^^

This value, updated by PowerDNS, is the unix timestamp of the last
successful attempt to check this zone for freshness on the master.

refresh
^^^^^^^

The number of seconds PowerDNS should wait after a successful freshness
check before performing another one. This value is also found in the
zone's SOA record. You may want to make sure to put the same thing in
both places.

serial
^^^^^^

The serial of the version of the zone's content we are hosting now. This
value is also found in the zone's SOA record. You may want to make sure
to put the same thing in both places.

notified\_serial
^^^^^^^^^^^^^^^^

The latest serial for which we have sent ``NOTIFY`` packets. Updated by
PowerDNS.

The Zonemasters and ZoneAlsoNotify Tables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These are lists of hosts PowerDNS will interact with for a zone in
master/slave mode. 'Zonemasters' lists the hosts PowerDNS will attempt
to pull zone transfers from, and accept 'NOTIFY' packets from.
'ZoneAlsoNotify' lists hosts PowerDNS will send 'NOTIFY' packets to, in
addition to any hosts that have NS records.

Host entries can be IPv4 or IPv6 addresses, in string representation. If
you need to specify a port, use ``192.0.2.4:5300`` notation for IPv4 and
brackets for IPv6: ``[2001:db8::1234]:5300``.

The Supermasters Table
~~~~~~~~~~~~~~~~~~~~~~

In superslave mode, PowerDNS can accept 'NOTIFY' packets for zones that
have not been defined in the zone table yet. PowerDNS will then create
an entry for the zone and attempt a zone transfer. This table defines
the list of acceptable sources for supernotifications.

name
^^^^

An identifying string for this entry. Only used for logging.

ip
^^

The alleged originating IP address of the notification.

nameserver
^^^^^^^^^^

The FQDN of an authoritative nameserver.

A supernotification will be accepted if an entry is found such that the
notification came from 'ip' and 'nameserver' appears in an NS record for
that zone.

The ZoneMetadata Table
~~~~~~~~~~~~~~~~~~~~~~

This is a per-zone key-value store for various things PowerDNS needs to
know that are not part of the zone's content or handled by other tables.
Depending on your needs, you may not want this to exist as an actual
table, but simulate this in PL/SQL instead.

The currently defined metadata types are:

'PRESIGNED'
^^^^^^^^^^^

If set to 1, PowerDNS should assume that DNSSEC signatures for this zone
exist in the database and use them instead of signing records itself.
For a slave zone, this will also signal to the master that we want
DNSSEC records when attempting a zone transfer.

'NSEC3PARAM'
^^^^^^^^^^^^

The NSEC3 hashing parameters for the zone.

'TSIG-ALLOW-AXFR'
^^^^^^^^^^^^^^^^^

The value is the name of a TSIG key. A client will be allowed to AXFR
from us if the request is signed with that key.

'AXFR-MASTER-TSIG'
^^^^^^^^^^^^^^^^^^

The value is the name of a TSIG key. Outgoing ``NOTIFY`` packets for
this zone will be signed with that key.

The Tables for Cryptographic Keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We have two of them: 'TSIGKeys' for symmetric TSIG keys, and
'ZoneDNSKeys' for DNSSEC signing keys.

The Records Table
~~~~~~~~~~~~~~~~~

The actual DNS zone contents are stored here.

zone\_id
^^^^^^^^

The zone this records belongs to. Normally, this is obvious. When you
are dealing with zone delegations, you have to insert some records into
the parent zone of their actual zone. See also ``auth``.

fqdn
^^^^

The owner name of this record. Again, this is lower case and without a
trailing dot.

revfqdn
^^^^^^^

This should be a string that consists of the labels of the owner name,
in reverse order, with spaces instead of dots separating them, for
example:

::

    'www.example.com' => 'com example www'

This is used as a quick and dirty way to get canonical zone ordering.
You can chose a more correct and much more complicated implementation
instead if you prefer. In the reference schema, this is automatically
set by a trigger.

fqdnhash
^^^^^^^^

The NSEC3 hash of the owner name. The reference schema provides code and
a trigger to calculate this, but they are not production quality. The
recommendation is to load the dnsjava classes into your database and use
their facilities for dealing with DNS names and NSEC3 hashes.

ttl
^^^

The TTL for the record set. This should be the same for all members of a
record set, but PowerDNS will quietly use the minimum if it encounters
different values.

type
^^^^

The type of the record, as a canonical identification string, e.g.
'AAAA' or 'MX'. You can set this and 'content' NULL to indicate a name
that exists, but doesn't carry any record (a so called empty
non-terminal) for NSEC/NSEC3 ordering purposes.

content
^^^^^^^

The data part of the DNS record, in canonical string representation,
except that if this includes FQDNs, they should be specified without a
trailing dot.

auth
^^^^

0 or 1 depending on whether this record is an authoritative member of
the zone specified in ``zone_id``. These are the rules for determining
that: A record is an authoritative member of the zone its owner name
belongs to, except for DS records, which are authoritative members of
the parent zone. Delegation records, that is, NS records and related
A/AAAA glue records, are additionally non-authoritative members of the
parent zone.

PowerDNS has a function to automatically set this. OracleBackend doesn't
support that. Do it in the database.

The SQL Statements
~~~~~~~~~~~~~~~~~~

Fetching DNS records
^^^^^^^^^^^^^^^^^^^^

There are five queries to do this. They all share the same set of return
columns:

-  fqdn: The owner name of the record.
-  ttl: The TTL of the record set.
-  type: The type of the record.
-  content: The content of the record.
-  zone\_id: The numerical identifier of the zone the record belongs to.
   A record can belong to two zones (delegations/glue), in which case it
   may be returned twice.
-  auth: 1 or 0 depending on the zone membership (authoritative or not).

Record sets (records for the same name of the same type) must appear
consecutively, which means **ORDER BY** clauses are needed in some
places. Empty non-terminals should be suppressed.

The queries differ in which columns are restricted by 'WHERE' clauses:

oracle-basic-query
''''''''''''''''''

Looking for records based on owner name and type. Default:

::

    SELECT fqdn, ttl, type, content, zone_id, last_change, auth
    FROM Records
    WHERE type = :type AND fqdn = lower(:name)

oracle-basic-id-query
'''''''''''''''''''''

Looking for records from one zone based on owner name and type. Default:

::

    SELECT fqdn, ttl, type, content, zone_id, last_change, auth
    FROM Records
    WHERE type = :type AND fqdn = lower(:name) AND zone_id = :zoneid

oracle-any-query
''''''''''''''''

Looking for records based on owner name. Default:

::

    SELECT fqdn, ttl, type, content, zone_id, last_change, auth
    FROM Records
    WHERE fqdn = lower(:name)
      AND type IS NOT NULL
    ORDER BY type

oracle-any-id-query
'''''''''''''''''''

Looking for records from one zone based on owner name. Default:

::

    SELECT fqdn, ttl, type, content, zone_id, last_change, auth
    FROM Records
    WHERE fqdn = lower(:name)
      AND zone_id = :zoneid
      AND type IS NOT NULL
    ORDER BY type

oracle-list-query
'''''''''''''''''

Looking for all records from one zone. Default:

::

    SELECT fqdn, ttl, type, content, zone_id, last_change, auth
    FROM Records
    WHERE zone_id = :zoneid
      AND type IS NOT NULL
    ORDER BY fqdn, type

Zone Metadata and TSIG
^^^^^^^^^^^^^^^^^^^^^^

oracle-get-zone-metadata-query
''''''''''''''''''''''''''''''

Fetch the content of the metadata entries of type ':kind' for the zone
called ':name', in their original order. Default:

::

    SELECT md.meta_content
    FROM Zones z JOIN ZoneMetadata md ON z.id = md.zone_id
    WHERE z.name = lower(:name) AND md.meta_type = :kind
    ORDER BY md.meta_ind

oracle-del-zone-metadata-query
''''''''''''''''''''''''''''''

Delete all metadata entries of type ':kind' for the zone called ':name'.
You can skip this if you do not plan to manage zones with the
``pdnsutil`` tool. Default:

::

    DELETE FROM ZoneMetadata md
    WHERE zone_id = (SELECT id FROM Zones z WHERE z.name = lower(:name))
    AND md.meta_type = :kind

oracle-set-zone-metadata-query
''''''''''''''''''''''''''''''

Create a metadata entry. You can skip this if you do not plan to manage
zones with the ``pdnsutil`` tool. Default:

::

    INSERT INTO ZoneMetadata (zone_id, meta_type, meta_ind, meta_content)
    VALUES (
      (SELECT id FROM Zones WHERE name = lower(:name)),
      :kind, :i, :content
    )

oracle-get-tsig-key-query
'''''''''''''''''''''''''

Retrieved the TSIG key specified by ':name'. Default:

::

    SELECT algorithm, secret
    FROM TSIGKeys
    WHERE name = :name

DNSSEC
^^^^^^

oracle-get-zone-keys-query
''''''''''''''''''''''''''

Retrieve the DNSSEC signing keys for a zone. Default:

::

    SELECT k.id, k.flags, k.active, k.keydata
    FROM ZoneDNSKeys k JOIN Zones z ON z.id = k.zone_id
    WHERE z.name = lower(:name)

oracle-del-zone-key-query
'''''''''''''''''''''''''

Delete a DNSSEC signing key. You can skip this if you do not plan to
manage zones with the ``pdnsutil`` tool. Default:

::

    DELETE FROM ZoneDNSKeys WHERE id = :keyid

oracle-add-zone-key-query
'''''''''''''''''''''''''

Add a DNSSEC signing key. You can skip this if you do not plan to manage
zones with the ``pdnsutil`` tool. Default:

::

    INSERT INTO ZoneDNSKeys (id, zone_id, flags, active, keydata) "
    VALUES (
      zonednskeys_id_seq.NEXTVAL,
      (SELECT id FROM Zones WHERE name = lower(:name)),
      :flags,
      :active,
      :content
    ) RETURNING id INTO :keyid

oracle-set-zone-key-state-query
'''''''''''''''''''''''''''''''

Enable or disable a DNSSEC signing key. You can skip this if you do not
plan to manage zones with the **pdnsutil** tool. Default:

::

    UPDATE ZoneDNSKeys SET active = :active WHERE id = :keyid

oracle-prev-next-name-query
'''''''''''''''''''''''''''

Determine the predecessor and successor of an owner name, in canonical
zone ordering. See the reference implementation for the quick and dirty
way, and the RFCs for the full definition of canonical zone ordering.

This statement is a PL/SQL block that writes into two of the bind
variables, not a query.

Default:

::

    BEGIN
      get_canonical_prev_next(:zoneid, :name, :prev, :next);
    END;

oracle-prev-next-hash-query
'''''''''''''''''''''''''''

Given an NSEC3 hash, this call needs to return its predecessor and
successor in NSEC3 zone ordering into ``:prev`` and ``:next``, and the
FQDN of the predecessor into ``:unhashed``. Default:

::

    BEGIN
      get_hashed_prev_next(:zoneid, :hash, :unhashed, :prev, :next);
    END;

Incoming AXFR
^^^^^^^^^^^^^

oracle-zone-info-query
''''''''''''''''''''''

Get some basic information about the named zone before doing
master/slave things. Default:

::

    SELECT id, name, type, last_check, serial, notified_serial
    FROM Zones
    WHERE name = lower(:name)

oracle-delete-zone-query
''''''''''''''''''''''''

Delete all records for a zone in preparation for an incoming zone
transfer. This happens inside a transaction, so if the transfer fails,
the old zone content will still be there. Default:

::

    DELETE FROM Records WHERE zone_id = :zoneid

oracle-insert-record-query
''''''''''''''''''''''''''

Insert a record into the zone during an incoming zone transfer. This
happens inside the same transaction as delete-zone, so we will not end
up with a partially transferred zone. Default:

::

    INSERT INTO Records (id, fqdn, zone_id, ttl, type, content)
    VALUES (records_id_seq.NEXTVAL, lower(:name), :zoneid, :ttl, :type, :content)

oracle-finalize-axfr-query
''''''''''''''''''''''''''

A block of PL/SQL to be executed after a zone transfer has successfully
completed, but before committing the transaction. A good place to locate
empty non-terminals, set the ``auth`` bit and NSEC3 hashes, and
generally do any post-processing your schema requires. The do-nothing
default:

::

    DECLARE
      zone_id INTEGER := :zoneid;
    BEGIN
      NULL;
    END;

Master/Slave Stuff
^^^^^^^^^^^^^^^^^^

oracle-unfresh-zones-query
''''''''''''''''''''''''''

Return a list of zones that need to be checked and their master servers.
Return multiple rows, identical except for the master address, for zones
with more than one master. Default:

::

    SELECT z.id, z.name, z.last_check, z.serial, zm.master
    FROM Zones z JOIN Zonemasters zm ON z.id = zm.zone_id
    WHERE z.type = 'SLAVE'
      AND (z.last_check IS NULL OR z.last_check + z.refresh < :ts)
    ORDER BY z.id

oracle-zone-set-last-check-query
''''''''''''''''''''''''''''''''

Set the last check timestamp after a successful check. Default:

::

    UPDATE Zones SET last_check = :lastcheck WHERE id = :zoneid

oracle-updated-masters-query
''''''''''''''''''''''''''''

Return a list of zones that need to have ``NOTIFY`` packets sent out.
Default:

::

    SELECT id, name, serial, notified_serial
    FROM Zones
    WHERE type = 'MASTER'
    AND (notified_serial IS NULL OR notified_serial < serial)

oracle-zone-set-notified-serial-query
'''''''''''''''''''''''''''''''''''''

Set the last notified serial after packets have been sent. Default:

::

    UPDATE Zones SET notified_serial = :serial WHERE id = :zoneid

oracle-also-notify-query
''''''''''''''''''''''''

Return a list of hosts that should be notified, in addition to any
nameservers in the NS records, when sending ``NOTIFY`` packets for the
named zone. Default:

::

    SELECT an.hostaddr
    FROM Zones z JOIN ZoneAlsoNotify an ON z.id = an.zone_id
    WHERE z.name = lower(:name)

oracle-zone-masters-query
'''''''''''''''''''''''''

Return a list of masters for the zone specified by id. Default:

::

    SELECT master
    FROM Zonemasters
    WHERE zone_id = :zoneid

oracle-is-zone-master-query
'''''''''''''''''''''''''''

Return a row if the specified host is a registered master for the named
zone. Default:

::

    SELECT zm.master
    FROM Zones z JOIN Zonemasters zm ON z.id = zm.zone_id
    WHERE z.name = lower(:name) AND zm.master = :master

Superslave Stuff
^^^^^^^^^^^^^^^^

oracle-accept-supernotification-query
'''''''''''''''''''''''''''''''''''''

If a supernotification should be accepted from ':ip', for the master
nameserver ':ns', return a label for this supermaster. Default:

::

    SELECT name
    FROM Supermasters
    WHERE ip = :ip AND nameserver = lower(:ns)

oracle-insert-slave-query
'''''''''''''''''''''''''

A supernotification has just been accepted, and we need to create an
entry for the new zone. Default:

::

    INSERT INTO Zones (id, name, type)
    VALUES (zones_id_seq.NEXTVAL, lower(:zone), 'SLAVE')
    RETURNING id INTO :zoneid

oracle-insert-master-query
''''''''''''''''''''''''''

We need to register the first master server for the newly created zone.
Default:

::

    INSERT INTO Zonemasters (zone_id, master)
    VALUES (:zoneid, :ip)
