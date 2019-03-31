ZSK Rollover
============

This how to describes the way to roll a ZSK that is not a secure
entrypoint (a ZSK that is not tied to a DS record in the parent zone)
using the :rfc:`"RFC 6781 Pre-Publish Zone Signing Key
Rollover" <6781#section-4.1.1.1>`
method. The documentation linked above also lists the minimum time
between stages. **PLEASE READ THAT DOCUMENT CAREFULLY**

First, create a new inactive ZSK for the zone (if one already exists,
you can skip this step), we add an ECDSA 256 bit key (algorithm 13)
here:

.. code-block:: shell

    pdnsutil add-zone-key example.net zsk inactive ecdsa256

You are now almost at the "new DNSKEY"-stage of the rollover, if the
zone is of type 'MASTER' you'll need to update the SOA serial in the
database and wait for the slaves to pickup the zone change.

To change the RRSIGs on your records, the new key must be made active.
Note: you can get the key-ids with ``pdnsutil show-zone example.net``:

.. code-block:: shell

    pdnsutil activate-zone-key example.net new-key-id
    pdnsutil deactivate-zone-key example.net previous-key-id

Again, if this is a 'MASTER'-zone, update the SOA serial. You are now at
the "new RRSIGs" stage of the roll over.

The last step is to remove the old key from the completely:

.. code-block:: shell

    pdnsutil remove-zone-key example.net previous-key-id

Don't forget to update the SOA serial for 'MASTER' zones. The rollover
is now at the "DNSKEY removal" stage and complete.

