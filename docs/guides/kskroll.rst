KSK Rollover
============

Before attempting a KSK rollover, please read :rfc:`RFC 6581 "DNSSEC
Operational Practices, Version 2", section 4 <6781#section-4>` carefully to
understand the terminology, actions and timelines (TTL and RRSIG expiry)
involved in rolling a KSK.

This How To describes the "Double-Signature Key Signing Key Rollover"
from the above mentioned RFC. The following instruction work for
both a KSK and a CSK.

To start the rollover, add an **active** new KSK to the zone
(example.net in this case):

.. code-block:: shell

    pdnsutil add-zone-key example.net ksk active

Note that a key with same algorithm as the KSK to be replaced should be
created, as this is not an algorithm roll over.

If this zone is of the type 'MASTER', increase the SOA serial. The
rollover is now in the "New KSK" stage. Retrieve the DS record(s) for
the new KSK:

.. code-block:: shell

    pdnsutil show-zone example.net

And communicate this securely to your registrar/parent zone, replacing
the existing data. Now wait until the new DS is published in the
parent zone and at least the TTL for the DS records has passed. The
rollover is now in the "DS Change" state and can continue to the
"DNSKEY Removal" stage by actually deleting the old KSK.

.. note::
  The key-id for the old KSK is shown in the output of
  ``pdnsutil show-zone example.net``.

.. code-block:: shell

    pdnsutil remove-zone-key example.net KEY-ID

If this zone is of the type 'MASTER', increase the SOA serial.
The rollover is now complete.
