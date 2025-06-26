KSK Rollover
============

Before attempting a KSK rollover, please read :rfc:`RFC 6781 "DNSSEC Operational Practices, Version 2", section 4 <6781#section-4>` carefully to understand the terminology, actions and timelines (TTL and RRSIG expiry) involved in rolling a KSK.

This How To describes the "Double-Signature" scheme from the above mentioned RFC, as specified in :rfc:`section 4.1.2 <6781#section-4.1.2>`.
Phases are named after the steps in the diagram in that section.

After every change, use your favourite DNSSEC checker (`DNSViz <https://dnsviz.net/>`__, `VeriSign DNSSEC Analyzer <https://dnssec-debugger.verisignlabs.com/>`__, a validating resolver) to make sure no mistakes have crept in.

.. warning::

    For every mutation to your zone make sure that your serial is bumped, so your secondaries pick up the changes too.
    If you are using AXFR replication, this usually is as simple as ``pdnsutil zone increase-serial example.com``

Phase: Initial
--------------

In the ``initial`` situation, we have a KSK and the parent zone contains a DS matching that KSK.
Assuming this situation has existed for a few days, or perhaps way longer, we can move on to the ``new DNSKEY`` phase without delay.

Phase: new DNSKEY
-----------------

At first note down algorithm of currently used KSK, because new KSK shall use the same one, by running following command:

.. code-block:: shell

    pdnsutil zone show example.com

To create a new **active** and **published** KSK with the same algorithm for the zone, run something like:

.. code-block:: shell

    pdnsutil zone add-key example.com ksk active published ALGORITHM

Please note down the key ID that ``zone add-key`` reports. You can also retrieve it later with ``pdnsutil zone show example.com``.

After this the DNSKEY set will be signed by both KSKs.

Please check that your secondaries now show both the old and new DNSKEYs when queried for them with ``dig DNSKEY example.com @...``.

Now that the new DNSKEY is active and published, we need to wait for caches to pick it up. Check the DNSKEY TTL and then wait for at least that long.

Phase: DS change
----------------

The DNSKEY set is currently signed with both KSKs and keys of both are published.
This means that a DS for either old or new KSK is sufficient for validation.
We can now switch the DS record in the parent zone - there is no need to have DSes for both KSKs in the parent zone.

Using ``pdnsutil zone show example.com`` or ``pdnsutil zone export-ds example.com``, extract the DNSKEY or DS for new KSK, depending on what the parent zone operator takes as input.
Note that these commands print DNSKEYs and/or DSes for both the old and the new KSK.

Check the DS TTL at the parent, for example: ``dig DS example.com @c.gtld-servers.net`` for a delegation from ``.com``.

Submit the new DNSKEY and/or DS for of new KSK to the parent, and make sure to delete those for the old KSK.

Check again with the parent to see whether the new DS is published.

Then, wait for at least as long as the TTL for the old DS was.

Phase: DNSKEY removal
---------------------

The parent DS is pointing at the new KSK and the old DS has expired from all caches.
However, both sets of DNSKEYs are still in caches.
It is time to remove the old DNSKEY:

.. code-block:: shell

    pdnsutil zone remove-key example.com OLD_KSK_ID
    
Please check that your secondaries now only show the new set of keys when queried with ``dig DNSKEY example.com @...``.

Conclusion
----------

After at least another DNSKEY TTL time the old DNSKEY shall expire from caches.

Your KSK Rollover is complete.
