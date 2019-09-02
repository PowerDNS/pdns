DNSSEC Modes of Operation
=========================

Traditionally, DNSSEC signatures have been added to unsigned zones, and
then this signed zone could be served by any DNSSEC capable
authoritative server. PowerDNS supports this mode fully.

In addition, PowerDNS supports taking care of the signing itself, in
which case PowerDNS operates differently from most tutorials and
handbooks. This mode is easier, however.

For relevant tradeoffs, please see :doc:`../security` and
:doc:`../performance`.

.. _dnssec-online-signing:

Online Signing
--------------

In the simplest situation, there is a single "SQL" database that
contains, in separate tables, all domain data, keying material, and other
DNSSEC related settings.

This database is then replicated to all PowerDNS instances, which all
serve identical records, keys, and signatures.

In this mode of operation, care should be taken that the database
replication occurs over a secure network, or over an encrypted
connection. If intercepted, keying material could be used to counterfeit
DNSSEC data using the original keys.

Such a single replicated database requires no further attention beyond
monitoring already required during non-DNSSEC operations.

Please note that the ALIAS record type is
:ref:`not supported <alias_and_dnssec>` in this mode.

Records, Keys, signatures, hashes within PowerDNS in online signing mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Within PowerDNS live signing, keys are stored separately from the zone
records. Zone data are only combined with signatures and keys when
requests come in over the internet.

Each zone can have a number of keys associated with it, with varying key
lengths. Typically 1 or at most 2 of these keys are employed as actual
Zone Signing Keys (ZSKs). During normal operations, this means that only
1 ZSK is 'active', and the other is inactive.

Should it be desired to 'roll over' to a new key, both keys can
temporarily be active (and used for signing), and after a while, the old
key can be deactivated. Subsequently, it can be removed.

As described above, there are several ways in which DNSSEC can deny the
existence of a record, and this setting, which is also stored away from zone
records, lives with the DNSSEC keying material.

.. _dnssec-nsec-modes:

(Hashed) Denial of Existence
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PowerDNS supports unhashed secure denial-of-existence using NSEC
records. These are generated with the help of the (database) backend,
which needs to be able to supply the 'previous' and 'next' records in
canonical ordering. NSEC is the default mode for secured zones in
PowerDNS.

The Generic SQL Backends have fields that allow them to supply these
relative record names.

In addition, hashed secure denial-of-existence is supported using NSEC3
records, in two modes, one with help from the database, the other with
the help of some additional calculations.

NSEC3 in 'broad' or 'inclusive' mode works with the aid of the backend,
where the backend should be able to supply the previous and next domain
names in hashed order. This is the default mode for NSEC3 in PowerDNS.

NSEC3 in 'narrow' mode uses additional hashing calculations to provide
hashed secure denial-of-existence 'on the fly' per
`RFC 7129 <https://tools.ietf.org/html/rfc7129>`__, without further
involving the database. This mode will make PowerDNS to send out "white
lies" and prevents zone enumeration, but these responses require online
signing capabilities by all nameservers and therefore denies incoming
AXFRs for zones in this mode.

.. _dnssec-signatures:

Signatures
~~~~~~~~~~

In PowerDNS live signing mode, signatures, as served through RRSIG
records, are calculated on the fly, and heavily cached. All CPU cores
are used for the calculation.

RRSIGs have a validity period. In PowerDNS, the RRSIG validity period is 3 weeks.
This period starts at most a week in the past and continues at least a week into the future.
This interval jumps with one-week increments every Thursday.

The time period used is always calculated based on the moment of rollover.
The inception timestamp is the most recent Thursday 00:00:00 UTC, which is exactly one week ago at the moment of rollover.
The expiry timestamp is the Thursday 00:00:00 UTC two weeks later from the moment of rollover.
Graphically, it looks like this::

  RRSIG(1) Inception                                                    RRSIG(1) Expiry
  |                                                                                   |
  v                                                                                   v
  |================================ RRSIG(1) validity ================================|
                              |================================ RRSIG(2) validity ================================|
                              ^                                                                                   ^
                              |                                                                                   |
                              RRSIG(2) Inception                                                    RRSIG(2) Expiry

                              |----- RRSIG(1) served -----|----- RRSIG(2) served -----|

  |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
  Thu Fri Sat Sun Mon Tue Wed Thu Fri Sat Sun Mon Tue Wed Thu Fri Sat Sun Mon Tue Wed Thu Fri Sat Sun Mon Tue Wed Thu
                                                          ^
                                                          |
                                                          RRSIG roll-over(1 to 2)

At all times, only one RRSIG per signed RRset per ZSK is served when responding to clients.

.. note::
  Why Thursday? POSIX-based operating systems count the time
  since GMT midnight January 1st of 1970, which was a Thursday. PowerDNS
  inception/expiration times are generated based on the integral number of
  weeks since the start of the 'epoch'.

PowerDNS also serves the DNSKEY records in live-signing mode. Their TTL
is derived from the SOA records *minimum* field. When using NSEC3, the
TTL of the NSEC3PARAM record is also derived from that field.

.. _dnssec_presigned_records:

Pre-signed records
------------------

In this mode, PowerDNS serves zones that already contain DNSSEC records.
Such zones can either be slaved from a remote master in online signing
mode, or can be pre-signed using tools like OpenDNSSEC, ldns-signzone,
and dnssec-signzone.

Even in this mode, PowerDNS will synthesize NSEC(3) records itself
because of its architecture. RRSIGs of these NSEC(3) will still need to
be imported. See the :ref:`Presigned migration guide <dnssec-migration-presigned>`.

Front-signing
-------------

As a special feature, PowerDNS can operate as a signing server which
operates as a slave to an unsigned master.

In this way, if keying material is available for an unsigned zone that
is retrieved from a master server, this keying material will be used
when serving data from this zone.

As part of the zone retrieval, the equivalent of
``pdnsutil rectify-zone`` is run to make sure that all DNSSEC-related
fields are set correctly in the backend.

Signed AXFR
-----------

An outgoing zone transfer from a signing master contains all information
required for the receiving party to rectify the zone without knowing the
keys, such as signed NSEC3 records for empty non-terminals. The zone is
not required to be rectified on the master.

The signing and hashing algorithms are described in :ref:`dnssec-online-signing`.

.. _dnssec-modes-bind-mode:

BIND-mode operation
-------------------

The :doc:`BIND backend <../backends/bind>` can manage keys and other
DNSSEC-related :doc:`domain metadata <../domainmetadata>` in an SQLite3
database without launching a separate gsqlite3 backend.

To use this mode, run
``pdnsutil create-bind-db /var/lib/powerdns/bind-dnssec-db.sqlite3`` and set
:ref:`setting-bind-dnssec-db` in pdns.conf to the path of the created
database. Then, restart PowerDNS.

.. note::
  This SQLite database is different from the database used for the regular :doc:`SQLite 3 backend <../backends/generic-sqlite3>`.

After this, you can use ``pdnsutil secure-zone`` and all other pdnsutil
commands on your BIND zones without trouble.

.. _dnssec-modes-hybrid-bind:

Hybrid BIND-mode operation
--------------------------

PowerDNS can also operate based on 'BIND'-style zone & configuration
files. This 'BIND backend' has full knowledge of DNSSEC but has no
native way of storing keying material.

However, since PowerDNS supports operation with multiple simultaneous
backends, this is not a problem.

In hybrid mode, keying material and zone records are stored in different
backends. This allows for 'BIND backend' operation in full DNSSEC mode.

To benefit from this mode, include at least one database-based backend
in the :ref:`setting-launch` statement. See the :doc:`backend specific documentation <../backends/index>`
on how to initialize the database and backend.

.. warning::
  For now, it is necessary to execute a manual SQL 'insert'
  into the domains table of the backend hosting the keying material. This
  is needed to generate a zone-id for the relevant domain. Sample SQL
  statement::

      insert into domains (name, type) values ('powerdnssec.org', 'NATIVE');

The :doc:`SQLite 3 backend <../backends/generic-sqlite3>` probably complements BIND mode best, since it does not require a database server process.

.. note::
  The sqlite3 database must be created using the normal schema for this backend.
  The database created with ``pdnsutil create-bind-db`` will not work in this backend.
