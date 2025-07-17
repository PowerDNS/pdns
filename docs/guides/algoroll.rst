Algorithm Rollover
==================

Before attempting an algorithm rollover, please read :rfc:`RFC 6781 "DNSSEC Operational Practices, Version 2", section 4 <6781#section-4>` carefully to understand the terminology, actions and timelines (TTL and RRSIG expiry) involved in changing DNSKEY algorithms.

This How To describes the "conservative" approach from the above mentioned RFC, as specified in :rfc:`section 4.1.4 <6781#section-4.1.4>`.
Phases are named after the steps in the diagram in that section.
The following instruction assume a KSK+ZSK setup; if you only have a CSK, ignore the ZSK steps.


After every change, use your favourite DNSSEC checker (`DNSViz <https://dnsviz.net/>`__, `VeriSign DNSSEC Analyzer <https://dnssec-debugger.verisignlabs.com/>`__, a validating resolver) to make sure no mistakes have crept in.

During this process, response sizes will be larger than usual, due to double sets of signatures, and double the amount of DNSKEYs.
Please check that these bigger packets can make it out of your network without trouble, and verify that you and your secondaries can serve queries over TCP as well.

.. warning::

    For every mutation to your zone (so, every step except updating DS in the parent), make sure that your serial is bumped, so your secondaries pick up the changes too.
    If you are using AXFR replication, this usually is as simple as ``pdnsutil
    zone increase-serial example.com`` (``pdnsutil increase-serial example.com``
    prior to version 5.0)

Phase: initial
--------------

In the ``initial`` situation, we have a KSK+ZSK with our old algorithm, and the parent zone contains a DS matching that KSK.
Assuming this situation has existed for a few days, or perhaps way longer, we can move on to the ``new RRSIGs`` phase without delay.

Phase: new RRSIGs
-----------------

To create signatures with the new algorithm, without publishing keys, run something like:

.. code-block:: shell

    pdnsutil zone add-key example.com KSK active unpublished ecdsa384
    pdnsutil zone add-key example.com ZSK active unpublished ecdsa384

or, prior to version 5.0:

.. code-block:: shell

    pdnsutil add-zone-key example.com KSK active unpublished ecdsa384
    pdnsutil add-zone-key example.com ZSK active unpublished ecdsa384

Note the key IDs that ``zone add-key`` reports.
You can also retrieve these later with ``pdnsutil zone show example.com``
(``pdnsutil show-zone example.com`` prior to version 5.0).

After this, PowerDNS will sign all records in the zone with both the old and new ZSKs, and the DNSKEY set will be signed by both KSKs.

Please check that your secondaries also show the new signatures.

In the next step, we will publish the new keys.
Once we do that, some validators will demand that those new keys also sign all records in the zone.
However, those validators may still have records signed with only the old ZSK in cache.
So, we need to wait for those records to expire.

In your zone, check for the highest TTL you can find.
This includes the SOA TTL and the SOA MINIMUM, which affect negative caching, including NSEC/NSEC3 records.
:ref:`The DNSKEY TTL is also taken from the SOA MINIMUM.<dnssec-ttl-notes>`

Now, wait for that long.
Depending on your setup, this will usually be between a few hours and a few days.

Phase: new DNSKEY
-----------------

In the previous step, we generated two new keys, and signed our zone with them, without actually exposing validators to the new keys.
After waiting for all records in our zone to expire from caches, we can publish the DNSKEYs:

.. code-block:: shell

    pdnsutil zone publish-key example.com 3
    pdnsutil zone publish-key example.com 4

or, prior to version 5.0:

.. code-block:: shell

    pdnsutil publish-zone-key example.com 3
    pdnsutil publish-zone-key example.com 4

Replace ``3`` and ``4`` with the key IDs gathered in the previous step, or find
them in the ``pdnsutil zone show`` output (``pdnsutil show-zone`` prior to
version 5.0).
PowerDNS will now publish the new DNSKEYs that have already been used for signing for a while.
The old DNSKEYs remain published, and active for signing, for now.

Please check that your secondaries now show both the old and new DNSKEYs when queried for them with ``dig DNSKEY example.com @...``.

Now that the new DNSKEYs are published, we again need to wait for caches to pick them up, before we switch DS records in the parent.

Check the DNSKEY TTL - then wait that long.

Phase: new DS
-------------

Our zone is currently fully signed with two algorithms, and keys for both algorithms are published.
This means that a DS for either the old or new algorithm is sufficient for validation.
We can now switch the DS - there is no need to have DSes for both algorithms in the parent zone.

Using ``pdnsutil zone show example.com`` or ``pdnsutil zone export-ds
example.com`` (``pdnsutil show-zone example.com`` or ``pdnsutil export-zone-ds
example.com`` prior to version 5.0), extract the new DNSKEYs or new DSes,
depending on what the parent zone operator takes as input.
Note that these commands print DNSKEYs and/or DSes for both the old and the new algorithm.

Check the DS TTL at the parent, for example: ``dig DS example.com @c.gtld-servers.net`` for a delegation from ``.com``.

Submit the new algorithm DNSKEY/DSes to the parent, and make sure to delete those for the old algorithm.

Check again with the parent to see whether the new DS is published.

Then, wait for as long as the TTL on the old DS was.

Phase: DNSKEY removal
---------------------

We are signing with two algorithms.
The parent DS is pointing at the KSK for the new algorithm, and the old DS has expired from all caches.
However, both sets of DNSKEYs are still in caches.
It is time to remove the old DNSKEYs, while keeping their signature:

.. code-block:: shell

    pdnsutil zone unpublish-key example.com 1
    pdnsutil zone unpublish-key example.com 2

or, prior to version 5.0:

.. code-block:: shell

    pdnsutil unpublish-zone-key example.com 1
    pdnsutil unpublish-zone-key example.com 2

Replace ``1`` and ``2`` with the IDs of the old keys.

Please check that your secondaries now only show the new set of keys when queried with ``dig DNSKEY example.com @...``.

Over the next DNSKEY TTL seconds, validators can still have both sets of keys in cache.
So, we leave our signatures in until that time passes.

Phase: RRSIGs removal
---------------------

After waiting DNSKEY TTL seconds, caches should only have a copy of our new set of keys.
This means we can now safely stop signing with the old keys:

.. code-block:: shell

    pdnsutil zone deactivate-key example.com 1
    pdnsutil zone deactivate-key example.com 2

or, prior to version 5.0:

.. code-block:: shell

    pdnsutil deactivate-zone-key example.com 1
    pdnsutil deactivate-zone-key example.com 2

Alternatively, you can use ``zone remove-key`` to remove all traces of the old keys.

Conclusion
----------

In another hours-to-a-few-days, the old signatures will expire from caches.

Your algorithm roll is complete.
