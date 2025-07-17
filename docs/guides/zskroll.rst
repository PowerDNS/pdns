ZSK Rollover
============

Before attempting a ZSK rollover, please read :rfc:`RFC 6781 "DNSSEC Operational Practices, Version 2", section 4 <6781#section-4>` carefully to understand the terminology, actions and timelines (TTL and RRSIG expiry) involved in rolling a ZSK.

This How To describes the "Pre-Publish" approach from the above mentioned RFC, as specified in :rfc:`section 4.1.1.1 <6781#section-4.1.1.1>`.
Phases are named after the steps in the diagram in that section.

.. warning::

    The following instructions assume rollover of a key which is NOT a Secure Entry Point (SEP), please confirm this fact before proceeding any further.

After every change, use your favourite DNSSEC checker (`DNSViz <https://dnsviz.net/>`__, `VeriSign DNSSEC Analyzer <https://dnssec-debugger.verisignlabs.com/>`__, a validating resolver) to make sure no mistakes have crept in.

.. warning::

    For every mutation to your zone make sure that your serial is bumped, so your secondaries pick up the changes too.
    If you are using AXFR replication, this usually is as simple as ``pdnsutil
    zone increase-serial example.com`` (``pdnsutil increase-serial example.com``
    prior to version 5.0)

Phase: Initial
--------------

In the ``initial`` situation, we have old ZSK key used to sign all the data in the zone.
Assuming this situation has existed for a few days, or perhaps way longer, we can move on to the ``new DNSKEY`` phase without delay.

Phase: new DNSKEY
-----------------

At first note down algorithm of currently used ZSK, because new ZSK shall use the same one, by running following command:

.. code-block:: shell

    pdnsutil zone show example.com

or, prior to version 5.0:

.. code-block:: shell

    pdnsutil show-zone example.com

To create a new **inactive** but **published** ZSK with the same algorithm, run something like:

.. code-block:: shell

    pdnsutil zone add-key example.com zsk inactive published ALGORITHM

or, prior to version 5.0:

.. code-block:: shell

    pdnsutil add-zone-key example.com zsk inactive published ALGORITHM

Please note down the key ID that ``zone add-key`` reports. You can also retrieve
it later with ``pdnsutil zone show example.com`` (``pdnsutil show-zone
example.com`` prior to version 5.0).

PowerDNS will now publish the new DNSKEY while the old DNSKEY remains published and active for signing.

Please check that your secondaries now show both the old and new DNSKEYs when queried for them with ``dig DNSKEY example.com @...``.

Now that the new DNSKEY is published, we need to wait for caches to pick it up. Check the DNSKEY TTL and then wait at least that long.

Phase: new RRSIGs
-----------------

To change the RRSIGs on records in the zone, the new DNSKEY must be made active and the old DNSKEY must be made inactive.

.. code-block:: shell

    pdnsutil zone activate-key example.com NEW-ZSK-ID
    pdnsutil zone deactivate-key example.com OLD-ZSK-ID

or, prior to version 5.0:

.. code-block:: shell

    pdnsutil activate-zone-key example.com NEW-ZSK-ID
    pdnsutil deactivate-zone-key example.com OLD-ZSK-ID

After this, PowerDNS will sign all records in the zone with the new ZSK and remove all signatures made with the old ZSK.

Please check that your secondaries now show only the new signatures.

In your zone, check for the highest TTL you can find.
This includes the SOA TTL and the SOA MINIMUM, which affect negative caching, including NSEC/NSEC3 records.
:ref:`The DNSKEY TTL is also taken from the SOA MINIMUM.<dnssec-ttl-notes>`

Now wait for at least that long.
Depending on your setup, this will usually be between a few hours and a few days.

Phase: DNSKEY removal
---------------------

The last step is to remove the old DNSKEY from the zone:

.. code-block:: shell

    pdnsutil zone remove-key example.com OLD-ZSK-ID

or, prior to version 5.0:

.. code-block:: shell

    pdnsutil remove-zone-key example.com OLD-ZSK-ID

Please check that your secondaries now show only the new DNSKEY when queried with ``dig DNSKEY example.com @...``.

Conclusion
----------

After at least another DNSKEY TTL time the old DNSKEY shall expire from caches.

Your ZSK Rollover is complete.
