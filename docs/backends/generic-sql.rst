Generic SQL Backends
====================

The generic SQL backends (like gmysql, gpgsql and godbc) are backends
with easily configurable SQL statements, allowing you to graft PowerDNS
on any SQL database of your choosing. Because all database schemas will
be different, a generic backend is needed to cover all needs.

.. warning::
  Host names and the MNAME of a SOA records are NEVER
  terminated with a '.' in PowerDNS storage! If a trailing '.' is present
  it will inevitably cause problems, problems that may be hard to debug.

.. note::
  A root zone or record should have a name of '.'
  (no quotes). This is the only exception to the 'no terminating dot in
  SQL storage' rule.

Basic functionality
-------------------

All domains in the generic SQL backends have a 'type' field that
describes the :doc:`../modes-of-operation`.

Native operation
^^^^^^^^^^^^^^^^

To add a domain, issue the following:

.. code-block:: SQL

    INSERT INTO domains (name, type) VALUES ('example.com', 'NATIVE');

The records table can now be filled by with the domain_id set to the id
of the domains table row just inserted.

Slave operation
^^^^^^^^^^^^^^^

These backends are fully slave capable. To become a slave of the
'example.com' domain, execute this:

.. code-block:: SQL

    INSERT INTO domains (name, master, type) VALUES ('example.com', '198.51.100.6', 'SLAVE');

And wait a while for PowerDNS to pick up the addition - which happens
within one minute (this is determined by the
:ref:`setting-slave-cycle-interval`
setting). There is no need to inform PowerDNS that a new domain was
added. Typical output is::

  Apr 09 13:34:29 All slave domains are fresh
  Apr 09 13:35:29 1 slave domain needs checking
  Apr 09 13:35:29 Domain example.com is stale, master serial 1, our serial 0
  Apr 09 13:35:30 [gPgSQLBackend] Connected to database
  Apr 09 13:35:30 AXFR started for 'example.com'
  Apr 09 13:35:30 AXFR done for 'example.com'
  Apr 09 13:35:30 [gPgSQLBackend] Closing connection

From now on, PowerDNS is authoritative for the 'example.com' zone and
will respond accordingly for queries within that zone.

Periodically, PowerDNS schedules checks to see if domains are still
fresh. The default
:ref:`setting-slave-cycle-interval` is 60
seconds, large installations may need to raise this value. Once a domain
has been checked, it will not be checked before its SOA refresh timer
has expired. Domains whose status is unknown get checked every 60
seconds by default.

PowerDNS has support for multiple masters per zone, separate master IP
addresses by commas:

.. code-block:: SQL

    INSERT INTO domains (name, master, type) VALUES ('example.com', '198.51.100.6, 2001:0DB8:15:4AF::4', 'SLAVE');

Superslave operation
^^^^^^^^^^^^^^^^^^^^

To configure a supermaster with IP address 203.0.113.53 which lists this
installation as 'autoslave.example.com', issue the following:

.. code-block:: SQL

    INSERT INTO supermasters VALUES ('203.0.113.53', 'autoslave.example.com', 'internal');

From now on, valid notifies from 203.0.113.53 that list a NS record
containing 'autoslave.example.com' will lead to the provisioning of a
slave domain under the account 'internal'. See :ref:`supermaster-operation`
for details.

Master operation
^^^^^^^^^^^^^^^^

The generic SQL backend is fully master capable with automatic discovery
of serial changes. Raising the serial number of a domain suffices to
trigger PowerDNS to send out notifications. To configure a domain for
master operation instead of the default native replication, issue:

.. code-block:: SQL

    INSERT INTO domains (name, type) VALUES ('example.com', 'MASTER');

Make sure that the assigned id in the domains table matches the
domain_id field in the records table!

.. _generic-sql-disabled-data:

Disabled data
^^^^^^^^^^^^^

PowerDNS understands the notion of disabled records. They are marked by
setting "disabled" to ``1`` (for PostgreSQL: ``true``). By extension,
when the SOA record for a domain is disabled, the entire domain is
considered to be disabled.

Effects: the record (or domain, respectively) will not be visible to DNS
clients. The REST API will still see the record (or domain). Even if a
domain is disabled, slaving still works. Slaving considers a disabled
domain to have a serial of 0; this implies that a slaved domain will not
stay disabled.

.. _generic-sql-handling-dnssec-signed-zones:

Handling DNSSEC signed zones
----------------------------

To enable DNSSEC processing, the ``backend-dnssec`` option must be set
to 'yes'.

.. _rules-for-filling-out-dnssec-fields:

Rules for filling out DNSSEC fields
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Two additional fields in the 'records' table are important: 'auth' and
'ordername'. These fields are set correctly on an incoming zone
transfer, and also by running ``pdnsutil rectify-zone``.

The 'auth' field should be set to '1' for data for which the zone itself
is authoritative, which includes the SOA record and its own NS records.

The 'auth' field should be 0 however for NS records which are used for
delegation, and also for any glue (A, AAAA) records present for this
purpose. Do note that the DS record for a secure delegation should be
authoritative!

The 'ordername' field needs to be filled out depending on the NSEC/NSEC3
mode. When running in NSEC3 'Narrow' mode, the ordername field is
ignored and best left empty. In NSEC/NSEC3 mode, the ordername field
should be NULL for any glue but filled in for all delegation NS records
and all authoritative records. In NSEC3 opt-out mode, ordername is NULL
for any glue and insecure delegation NS records, but filled in for
secure delegation NS records and all authoritative records.

In 'NSEC' mode, it should contain the *relative* part of a domain name,
in reverse order, with dots replaced by spaces. So
'www.uk.powerdnssec.org' in the 'powerdnssec.org' zone should have 'uk
www' as its ordername.

In 'NSEC3' non-narrow mode, the ordername should contain a lowercase
base32hex encoded representation of the salted & iterated hash of the
full record name. ``pdnsutil hash-zone-record zone record`` can be used
to calculate this hash.

In addition, PowerDNS fully supports empty non-terminals. If you have a
zone example.com, and a host a.b.c.example.com in it, rectify-zone (and
the AXFR client code) will insert b.c.example.com and c.example.com in
the records table with type NULL (SQL NULL, not 'NULL'). Having these
entries provides several benefits. We no longer reply NXDOMAIN for these
shorter names (this was an RFC violation but not one that caused
trouble). But more importantly, to do NSEC3 correctly, we need to be
able to prove existence of these shorter names. The type=NULL records
entry gives us a place to store the NSEC3 hash of these names.

If your frontend does not add empty non-terminal names to records, you
will get DNSSEC replies of 3.1-quality, which has served many people
well, but might lead to issues in the future.

.. _generic-sql-queries:

Queries
-------

From version 4.0.0 onward, the generic SQL backends use prepared
statements for their queries. Before 4.0.0, queries were expanded using
the C function 'snprintf' which implies that substitutions are performed
on the basis of %-placeholders.

To see the default queries for a backend, run
``pdns_server --no-config --launch=BACKEND --config``.

Regular Queries
^^^^^^^^^^^^^^^

For regular operation, several queries are used for record-lookup. These
queries must return the following fields in order:

-  content: This is the 'right hand side' of a DNS record. For an A
   record, this is the IP address for example.
-  ttl: TTL of this record, in seconds. Must be a positive integer, no
   checking is performed.
-  prio: For MX and SRV records, this should be the priority of the
   record specified.
-  type: The ASCII representation of the qtype of this record. Examples
   are 'A', 'MX', 'SOA', 'AAAA'. Make sure that this field returns an
   exact answer - PowerDNS won't recognise 'A ' as 'A'. This can be
   achieved by using a VARCHAR instead of a CHAR.
-  domain_id: Unique identifier for this domain. This id must be unique
   across all backends. Must be a positive integer.
-  disabled: Boolean, if set to true, this record is hidden from DNS
   clients, but can still be modified from the REST API. See :ref:`generic-sql-disabled-data`.
-  name: Actual name of a record. Must not end in a '.' and be fully
   qualified - it is not relative to the name of the domain!
-  auth: A boolean describing if PowerDNS is authoritative for this
   record (DNSSEC)

Please note that the names of the fields are not relevant, but the order
is!

-  ``basic-query``: This is the most used query, needed for doing 1:1
   lookups of qtype/name values.
-  ``id-query``: Used for doing lookups within a domain.
-  ``any-query``: For doing ANY queries. Also used internally.
-  ``any-id-query``: For doing ANY queries within a domain. Also used
   internally.
-  ``list-query``: For doing AXFRs, lists all records in the zone. Also
   used internally.
-  ``list-subzone-query``: For doing RFC 2136 DNS Updates, lists all
   records below a zone.
-  ``search-records-query``: To search for records on name and content.

DNSSEC queries
^^^^^^^^^^^^^^

These queries are used by e.g. ``pdnsutil rectify-zone``. Make sure to
read :ref:`rules-for-filling-out-dnssec-fields`
if you wish to calculate ordername and auth without using pdns-rectify.

-  ``insert-empty-non-terminal-order-query``: Insert empty non-terminal
   in zone.
-  ``delete-empty-non-terminal-query``: Delete an empty non-terminal in
   a zone.
-  ``remove-empty-non-terminals-from-zone-query``: remove all empty
   non-terminals from zone.

-  ``get-order-first-query``: DNSSEC Ordering Query, first.
-  ``get-order-before-query``: DNSSEC Ordering Query, before.
-  ``get-order-after-query``: DNSSEC Ordering Query, after.
-  ``get-order-last-query``: DNSSEC Ordering Query, last.
-  ``update-ordername-and-auth-query``: DNSSEC update ordername and auth
   for a qname query.
-  ``update-ordername-and-auth-type-query``: DNSSEC update ordername and
   auth for a rrset query.
-  ``nullify-ordername-and-update-auth-query``: DNSSEC nullify ordername
   and update auth for a qname query.
-  ``nullify-ordername-and-update-auth-type-query``: DNSSEC nullify
   ordername and update auth for a rrset query.

Domain and zone manipulation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  ``is-our-domain-query``: Checks if the domain (either id or name) is
   in the 'domains' table. This query is run before any other (possibly
   heavy) query.

-  ``insert-zone-query``: Add a new domain. This query also requires the
   type, masters and account fields
-  ``update-kind-query``: Called to update the type of domain.
-  ``delete-zone-query`` Called to delete all records of a zone. Used
   before an incoming AXFR.
-  ``delete-domain-query``: Called to delete a domain from the
   domains-table.

-  ``get-all-domains-query``: Used to get information on all active
   domains.
-  ``info-zone-query``: Called to retrieve (nearly) all information for
   a domain.

-  ``insert-record-query``: Called during incoming AXFR.
-  ``update-account-query``: Set the account for a domain.
-  ``delete-names-query``: Called to delete all records of a certain
   name.
-  ``delete-rrset-query``: Called to delete an RRset based on
   domain_id, name and type.

-  ``get-all-domain-metadata-query``: Get all
   :doc:`domain metadata <../domainmetadata>` for a domain.
-  ``get-domain-metadata-query``: Get a single piece of
   :doc:`domain metadata <../domainmetadata>`.
-  ``clear-domain-metadata-query``: Delete a single entry of domain
   metadata.
-  ``clear-domain-all-metadata-query``: Remove all domain metadata for a
   domain.
-  ``set-domain-metadata-query``: Add domain metadata for a zone.

-  ``add-domain-key-query``: Called to a cryptokey to a domain.
-  ``list-domain-keys-query``: Called to get all cryptokeys for a
   domain.
-  ``activate-domain-key-query``: Called to set a cryptokey to active.
-  ``deactivate-domain-key-query``: Called to set a cryptokey to
   inactive.
-  ``clear-domain-all-keys-query``: Called to remove all DNSSEC keys for
   a zone.
-  ``remove-domain-key-query``: Called to remove a crypto key.

Master/slave queries
^^^^^^^^^^^^^^^^^^^^

These queries are used to manipulate the master/slave information in the
database. Most installations will have zero need to change the following
queries.

On masters
~~~~~~~~~~

-  ``info-all-master-query``: Called to get data on all domains for
   which the server is master.
-  ``update-serial-query`` Called to update the last notified serial of
   a master domain.

On slaves
~~~~~~~~~

-  ``info-all-slaves-query``: Called to retrieve all slave domains.
-  ``update-lastcheck-query``: Called to update the last time a slave
   domain was successfully checked for freshness.
-  ``update-master-query``: Called to update the master address of a
   domain.

On superslaves
~~~~~~~~~~~~~~

-  ``supermaster-query``: Called to determine if a certain host is a
   supermaster for a certain domain name.
-  ``supermaster-name-to-ips``: Called to the IP and account for a
   supermaster.

TSIG
^^^^

-  ``get-tsig-key-query``: Called to get the algorithm and secret from a
   named TSIG key.
-  ``get-tsig-keys-query``: Called to get all TSIG keys.
-  ``set-tsig-key-query``: Called to set the algorithm and secret for a
   named TSIG key.
-  ``delete-tsig-key-query``: Called to delete a named TSIG key.

Comment queries
^^^^^^^^^^^^^^^

For listing/modifying comments.

-  ``list-comments-query``: Called to get all comments in a zone.
   Returns fields: domain_id, name, type, modified_at, account,
   comment.
-  ``insert-comment-query`` Called to create a single comment for a
   specific RRSet. Given fields: domain_id, name, type, modified_at,
   account, comment
-  ``delete-comment-rrset-query``: Called to delete all comments for a
   specific RRset. Given fields: domain_id, name, type
-  ``delete-comments-query``: Called to delete all comments for a zone.
   Usually called before deleting the entire zone. Given fields:
   domain_id
-  ``search-comments-query``: Called to search for comment by name or
   content.

Specifying queries
^^^^^^^^^^^^^^^^^^

The queries above are specified in pdns.conf. For example, the
basic-query for the Generic MySQL backend would appear as:

::

    gmysql-basic-query=SELECT content,ttl,prio,type,domain_id,disabled,name,auth FROM records WHERE disabled=0 and type=? and name=?

Queries can span multiple lines, like this:

::

    gmysql-basic-query=SELECT content,ttl,prio,type,domain_id,disabled,name,auth \
    FROM records WHERE disabled=0 and type=? and name=?
