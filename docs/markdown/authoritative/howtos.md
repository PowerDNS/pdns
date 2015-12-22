# Using ALIAS records
The ALIAS record provides a way to have CNAME-like behaviour on the zone apex.

In order to correctly serve ALIAS records, set the [`recursor`](settings.md#recursor)
setting to an existing resolver and add the ALIAS record to your zone apex. e.g.:

```
recursor=[::1]:5300
```

```
$ORIGIN example.net
$TTL 1800

@ IN SOA ns1.example.net. hostmaster.example.net. 2015121101 1H 15 1W 2H

@ IN NS ns1.example.net.

@ IN ALIAS mywebapp.paas-provider.net.
```

When the authoritative server receives a query for the A-record for `example.net`,
it will resolve the A record for `mywebapp.paas-provider.net` and serve an answer
for `example.net` with that A record.

# CDS & CDNSKEY Key Rollover
If the upstream registry supports [RFC 7344](https://tools.ietf.org/html/rfc7344)
key rollovers you can use several [`pdnsutil`](dnssec.md#pdnsutil) commands to do
this rollover. This HowTo follows the rollover example from the RFCs [Appendix B](https://tools.ietf.org/html/rfc7344#appendix-B).

We assume the zone name is example.com and is already DNSSEC signed.

Start by adding a new KSK to the zone: `pdnsutil add-zone-key example.com ksk 2048 inactive`.
The "inactive" means that the key is not used to sign any ZSK records. This limits
the size of `ANY` and DNSKEY responses.

Publish the CDS records: `pdnsutil set-publish-cds example.com`, these records
will tell the parent zone to update its DS records. Now wait for the DS records
to be updated in the parent zone.

Once the DS records are updated, do the actual key-rollover: `pdnsutil activate-zone-key example.com new-key-id`
and `pdnsutil deactivate-zone-key example.com old-key-id`. You can get the `new-key-id`
and `old-key-id` by listing them through `pdnsutil show-zone example.com`.

After the rollover, wait *at least* until the TTL on the DNSKEY records have
expired so validating resolvers won't mark the zone as BOGUS. When the wait is
over, delete the old key from the zone: `pdnsutil remove-zone-key example.com old-key-id`.
This updates the CDS records to reflect only the new key.

Wait for the parent to pick up on the CDS change. Once the upstream DS records
show only the DS records for the new KSK, you may disable sending out the CDS
responses: `pdnsutil unset-pushish-cds example.com`.

Done!
