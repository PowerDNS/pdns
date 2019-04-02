Operational instructions
========================

Several How to's describe operational practices with DNSSEC:

-  :doc:`../guides/kskroll`
-  :doc:`../guides/kskrollcdnskey`
-  :doc:`../guides/zskroll`

Below, frequently used commands are described:

Publishing a DS
---------------

To publish a DS to a parent zone, utilize ``pdnsutil show-zone`` and
take the DS from its output, and transfer it securely to your parent
zone.

Going insecure
--------------

.. code-block:: shell

    pdnsutil disable-dnssec ZONE

.. warning::
  Going insecure with a zone that has a DS record in the
  parent zone will make the zone BOGUS. Make sure the parent zone removes
  the DS record *before* going insecure.

.. _dnssec-operational-nsec-modes-params:

Setting the NSEC modes and parameters
-------------------------------------

As stated earlier, PowerDNS uses NSEC by default. If you want to use
NSEC3 instead, issue:

.. code-block:: shell

    pdnsutil set-nsec3 ZONE [PARAMETERS] ['narrow']

e.g.

.. code-block:: shell

    pdnsutil set-nsec3 example.net '1 0 1 ab'

The quoted part is the content of the NSEC3PARAM records, as defined in
:rfc:`5155 <5155#section-4>`, in order:

-  Hash algorithm, should always be ``1`` (SHA1)
-  Flags, set to ``1`` for :rfc:`NSEC3 Opt-out <5155#section-6>`, this best
   set as ``0``
-  Number of iterations of the hash function, read :rfc:`RFC 5155, Section
   10.3 <5155#section-10.3>` for recommendations. Limited by the
   :ref:`setting-max-nsec3-iterations` setting.
-  Salt to apply during hashing, in hexadecimal, or ``-`` to use no salt

Optionally, NSEC3 can be set to 'narrow' mode. For more information refer
to :ref:`dnssec-nsec-modes`.

To convert a zone from NSEC3 to NSEC operations, run:

.. code-block:: shell

    pdnsutil unset-nsec3 ZONE

.. warning::
  Don't change from NSEC to NSEC3 (or the other way around)
  for zones with algorithm 5 (RSASHA1), 6 (DSA-NSEC3-SHA1) or 7
  (RSASHA1-NSEC3-SHA1).

.. _soa-edit-ensure-signature-freshness-on-slaves:

SOA-EDIT: ensure signature freshness on slaves
----------------------------------------------

As RRSIGs can expire, slave servers need to know when to re-transfer the
zone. In most implementations (BIND, NSD), this is done by re-signing
the full zone outside of the nameserver, increasing the SOA serial and
serving the new zone on the master.

With PowerDNS in Live-signing mode, the SOA serial is not increased by
default when the RRSIG dates are rolled.

For zones that use :ref:`native-operation`
replication PowerDNS will serve valid RRSIGs on all servers.

For :ref:`master <master-operation>` zones (where
replication happens by means of AXFR), PowerDNS slaves will
automatically re-transfer the zone when it notices the RRSIGs have
changed, even when the SOA serial is not increased. This ensures the
zone never serves old signatures.

If your DNS setup uses non-PowerDNS slaves, the slaves need to know when
the signatures have been updated. This can be accomplished by setting
the :ref:`metadata-soa-edit` metadata for DNSSEC signed
zones. This value controls how the value of the SOA serial is modified
by PowerDNS.

.. note::
  The SOA serial in the datastore will be untouched, SOA-EDIT is
  applied to DNS answers with the SOA record.

The :ref:`setting-default-soa-edit` or
:ref:`setting-default-soa-edit-signed`
configuration options can instead be set to ensure SOA-EDIT is set for
every zone.

Possible SOA-EDIT values
~~~~~~~~~~~~~~~~~~~~~~~~

The 'inception' refers to the time the RRSIGs got updated in
:ref:`live-signing mode <dnssec-online-signing>`. This happens every week (see
:ref:`dnssec-signatures`). The inception time does not depend on
local timezone, but some modes below will use localtime for
representation.

INCREMENT-WEEKS
^^^^^^^^^^^^^^^

Increments the serial with the number of weeks since the UNIX epoch.
This should work in every setup; but the result won't look like
YYYYMMDDSS anymore.

For example: a serial of 12345678 will become 12348079 on Wednesday 13th
of January 2016 (2401 weeks after the epoch).

INCEPTION-EPOCH
^^^^^^^^^^^^^^^

Sets the new SOA serial number to the maximum of the old SOA serial
number, and age in seconds of the last inception. This requires your
backend zone to use the number of seconds since the UNIX epoch as SOA
serial. The result is still the age in seconds of the last change to the
zone, either by operator changes to the zone or the 'addition' of new
RRSIGs.

As an example, a serial of 12345678 becomes 1452124800 on Wednesday 13th
of January 2016.

INCEPTION-INCREMENT
^^^^^^^^^^^^^^^^^^^

Uses YYYYMMDDSS format for SOA serial numbers. If the SOA serial from
the backend is within two days after inception, it gets incremented by
two (the backend should keep SS below 98). Otherwise it uses the maximum
of the backend SOA serial number and inception time in YYYYMMDD01
format. This requires your backend zone to use YYYYMMDDSS as SOA serial
format. Uses localtime to find the day for inception time.

This changes a serial of 2015120810 to 2016010701 on Wednesday 13th of
January 2016.

INCEPTION (not recommended)
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. deprecated:: 4.1.0
  Removed in this release

Sets the SOA serial to the last inception time in YYYYMMDD01 format.
Uses localtime to find the day for inception time.

.. warning::
  The SOA serial will only change on inception day, so
  changes to the zone will get visible on slaves only on the following
  inception day.

INCEPTION-WEEK (not recommended)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. deprecated:: 4.1.0
  Removed in this release

Sets the SOA serial to the number of weeks since the epoch, which is the
last inception time in weeks.

.. warning::
  Same problem as INCEPTION.

EPOCH
^^^^^

Sets the SOA serial to the number of seconds since the epoch.

.. warning::
  Don't combine this with AXFR - the slaves would keep
  refreshing all the time. If you need fast updates, sync the backend
  databases directly with incremental updates (or use the same database
  server on the slaves)

NONE
^^^^

Ignore :ref:`setting-default-soa-edit` and/or
:ref:`setting-default-soa-edit-signed`
settings.

Security
--------

During typical PowerDNS operation, the private part of the signing keys
are 'online', which can be compared to operating an HTTPS server, where
the private key is available on the webserver for cryptographic
purposes.

In some settings, having such (private) keying material available online
is considered undesirable. In this case, consider running in pre-signed
mode.

A slightly more complex approach is running a *hidden* master in simple
online signing mode, but on a highly secured system unreachable for the
public. Internet-connected slaves can then transfer the zones pre-signed
from this master over a secure private network. This topology offers
substantial security benefits with regards to key material while
maintaining ease of daily operation by PowerDNS's features in online
mode.

See also :ref:`dnssec_presigned_records`.

Performance
-----------

DNSSEC has a performance impact, mostly measured in terms of additional
memory used for the signature caches. In addition, on startup or
AXFR-serving, a lot of signing needs to happen.

Most best practices are documented in :rfc:`6781`.
