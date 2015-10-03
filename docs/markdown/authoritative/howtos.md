# CDS & CDNSKEY Key Rollover
If the upstream registry supports [RFC 7344](https://tools.ietf.org/html/rfc7344)
key rollovers you can use several [`pdnssec`](dnssec.md#pdnssec) commands to do
this rollover. This HowTo follows the rollover example from the RFCs [Appendix B](https://tools.ietf.org/html/rfc7344#appendix-B).

We assume the zone name is example.com and is already DNSSEC signed.

Start by adding a new KSK to the zone: `pdnssec add-zone-key example.com ksk 2048 passive`.
The "passive" means that the key is not used to sign any ZSK records. This limits
the size of `ANY` and DNSKEY responses.

Publish the CDS records: `pdnssec set-publish-cds example.com`, these records
will tell the parent zone to update its DS records. Now wait for the DS records
to be updated in the parent zone.

Once the DS records are updated, do the actual key-rollover: `pdnssec activate-zone-key example.com new-key-id`
and `pdnssec deactivate-zone-key example.com old-key-id`. You can get the `new-key-id`
and `old-key-id` by listing them through `pdnssec show-zone example.com`.

After the rollover, wait *at least* until the TTL on the DNSKEY records have
expired so validating resolvers won't mark the zone as BOGUS. When the wait is
over, delete the old key from the zone: `pdnssec remove-zone-key example.com old-key-id`.
This updates the CDS records to reflect only the new key.

Wait for the parent to pick up on the CDS change. Once the upstream DS records
show only the DS records for the new KSK, you may disable sending out the CDS
responses: `pdnssec unset-pushish-cds example.com`.

Done!
