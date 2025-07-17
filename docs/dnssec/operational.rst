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

    pdnsutil set-nsec3 example.net '1 0 0 -'

The quoted part is the content of the NSEC3PARAM records, as defined in
:rfc:`RFC 5155 <5155#section-4>`, in order:

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

.. _soa-edit-ensure-signature-freshness-on-secondaries:

SOA-EDIT: ensure signature freshness on secondaries
---------------------------------------------------

As RRSIGs can expire, secondary servers need to know when to re-transfer the
zone. In most implementations (BIND, NSD), this is done by re-signing
the full zone outside of the nameserver, increasing the SOA serial and
serving the new zone on the primary.

With PowerDNS in Live-signing mode, the SOA serial is not increased by
default when the RRSIG dates are rolled.

For zones that use :ref:`native-operation`
replication PowerDNS will serve valid RRSIGs on all servers.

For :ref:`primary <primary-operation>` zones (where
replication happens by means of AXFR), PowerDNS secondaries will
automatically re-transfer the zone when it notices the RRSIGs have
changed, even when the SOA serial is not increased. This ensures the
zone never serves old signatures.

If your DNS setup uses non-PowerDNS secondaries, the secondaries need to know
when the signatures have been updated. This can be accomplished by setting
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

The 'inception' refers to the time that the RRSIGs got updated in
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

Uses the YYYYMMDDSS format for SOA serial numbers. The "inception day" is determined using localtime to get the start of the current signing week (usually Sunday).

- At the start of the DNSSEC signing inception week, the SOA serial is set to YYYYMMDD01 (skipping 00).
- If the current serial is less than YYYYMMDD00, it jumps directly to YYYYMMDD01.
- If the serial is exactly YYYYMMDD00 or YYYYMMDD01, it jumps to YYYYMMDD02.
- If the serial is within 3 days (until YYYYMMDD+2 at SS=99), it is incremented by 1.
- Otherwise, the serial remains unchanged.

**Important Notes**:
- Avoid using SS=00 in backend zones, as it may prevent proper zone transfers (AXFR/IXFR) to secondaries.
- Serial overflow can occur if more than 99 updates are made in a single day.
- This logic is not safe for zones with non-PowerDNS secondaries, as updates may not be detected reliably.

For full safety with non-PowerDNS secondaries, consider using `SOA-EDIT=DEFAULT` or managing serials explicitly.

**Example**:

Assume today is 2025-07-10 (Thursday) and the backend SOA serial is:

- ``2025070901``  becomes ``2025070902`` (still within the 3-day inception window)
- ``2025070800``  becomes ``2025070801`` (within the window, SS < 99)
- ``2025070701``  remains unchanged (outside the window)

EPOCH
^^^^^

Sets the SOA serial to the number of seconds since the epoch.

.. warning::
  Don't combine this with AXFR - the secondaries would keep
  refreshing all the time. If you need fast updates, sync the backend
  databases directly with incremental updates (or use the same database
  server on the secondaries)

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

A slightly more complex approach is running a *hidden* primary in simple
online signing mode, but on a highly secured system unreachable for the
public. Internet-connected secondaries can then transfer the zones pre-signed
from this primary over a secure private network. This topology offers
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

.. _dnssec-ttl-notes:

Some notes on TTL usage
-----------------------

In zones signed by PowerDNS (so non-presigned zones), some TTL values need to be filled in by PowerDNS.
The TTL of RRSIG record sets is the TTL of the covered RRset.
For CDS, CDNSKEY, DNSKEY, NSEC, NSEC3 and NSEC3PARAM, we use the SOA minimum (the last number in the SOA record).
Except for CDS/CDNSKEY/DNSKEY, these TTLs are chosen because `RFC 4034 <https://tools.ietf.org/html/rfc4034>`__ demands it so.

If you want a 'normal' TTL (3600, 86400, etc.) for your DNSKEY but a low TTL on negative answers, set your SOA minimum TTL to the high number, and set the TTL on the SOA record itself to the low TTL you want for negative answers.
Note that the NSEC/NSEC3 records proving those negatives will get the high TTL in that case, and this may affect subsequent resolution in resolvers that do aggressive NSEC caching (`RFC 8198 <https://tools.ietf.org/html/rfc8198>`__).

.. note::

  NSEC/NSEC3 records get the negative TTL (which is the lowest of the SOA TTL and the SOA minimum), which means their TTL matches that of a response such as NXDOMAIN.
  This conforms to :rfc:`RFC 9077 <9077#section-3>`.

  Prior to version 4.3.0, the behaviour was based on language in :rfc:`RFC 4034 <4034>` and :rfc:`RFC 5155 <5155>` about the NSEC/NSEC3 TTL.
