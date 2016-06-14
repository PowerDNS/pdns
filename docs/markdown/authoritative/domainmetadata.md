# Per zone settings aka Domain Metadata
Each served zone can have "metadata". Such metadata determines how this zone
behaves in certain circumstances.

**Warning**: Domain metadata is only available for DNSSEC capable backends! Make
sure to enable the proper '-dnssec' setting to benefit, and to have performed
the DNSSEC schema update.

For the BIND backend, this information is either stored in the
[`bind-dnssec-db`](backend-bind.md) or the hybrid database, depending on your
settings.

For the implementation in non-sql backends, please review your backend's documentation.

## ALLOW-AXFR-FROM
Starting with the PowerDNS Authoritative Server 3.1, per-zone AXFR ACLs can be
stored in the domainmetadata table.

Each ACL row can list one subnet (v4 or v6), or the magical value 'AUTO-NS' that
tries to allow all potential slaves in.

Example:

```
select id from domains where name='example.com';
7
insert into domainmetadata (domain_id, kind, content) values (7,'ALLOW-AXFR-FROM','AUTO-NS');
insert into domainmetadata (domain_id, kind, content) values (7,'ALLOW-AXFR-FROM','2001:db8::/48');
```

To dissallow all IP's, except those explicitly allowed by domainmetadata records, add `allow-axfr-ips=` to `pdns.conf`.

## AXFR-SOURCE
The IP address to use as a source address for sending AXFR and IXFR requests.

## ALLOW-DNSUPDATE-FROM, TSIG-ALLOW-DNSUPDATE, FORWARD-DNSUPDATE, SOA-EDIT-DNSUPDATE
See the documentation on [Dynamic DNS update](dnsupdate.md)

## ALSO-NOTIFY
When notifying this domain, also notify this nameserver (can occur multiple times).
The nameserver may have contain an optional port number. e.g.:

```
insert into domainmetadata (domain_id, kind, content) values (7,'ALSO-NOTIFY','192.0.2.1:5300');
insert into domainmetadata (domain_id, kind, content) values (7,'ALLOW-AXFR-FROM','2001:db8:53::1');
```

## AXFR-MASTER-TSIG
Use this named TSIG key to retrieve this zone from its master, see
[Provisioning signed notification and AXFR requests](tsig.md#provisioning-signed-notification-and-axfr-requests).

## GSS-ALLOW-AXFR-PRINCIPAL
Allow this GSS principal to perform AXFR retrieval. Most commonly it is
`host/something@REALM`, `DNS/something@REALM` or `user@REALM`. (See
[GSS-TSIG support](tsig.md#gss-tsig-support)).

## GSS-ACCEPTOR-PRINCIPAL
Use this principal for accepting GSS context. (See [GSS-TSIG support](tsig.md#gss-tsig-support)).

## IXFR
If set to 1, attempt IXFR when retrieving zone updates. Otherwise IXFR is not attempted.

## LUA-AXFR-SCRIPT
Script to be used to edit incoming AXFRs, see [Modifying a slave zone using a script](modes-of-operation.md#modifying-a-slave-zone-using-a-script).

## NSEC3NARROW
Set to "1" to tell PowerDNS this zone operates in NSEC3 'narrow' mode. See
`set-nsec3` for [`pdnsutil`](dnssec.md#pdnsutil).

## NSEC3PARAM
NSEC3 parameters of a DNSSEC zone. Will be used to synthesize the NSEC3PARAM
record. If present, NSEC3 is used, if not present, zones default to NSEC. See
`set-nsec3` in [`pdnsutil`](dnssec.md#pdnsutil). Example content: "1 0 1 ab".

## PRESIGNED
This zone carries DNSSEC RRSIGs (signatures), and is presigned. PowerDNS sets
this flag automatically upon incoming zone transfers (AXFR) if it detects DNSSEC
records in the zone. However, if you import a presigned zone using `zone2sql` or
`pdnsutil load-zone` you must explicitly set the zone to be `PRESIGNED`. Note that
PowerDNS will not be able to correctly serve the zone if the imported data is
bogus or incomplete. Also see `set-presigned` in [`pdnsutil`](dnssec.md#pdnsutil).

If a zone is presigned, the content of the metadata must be "1" (without the
quotes). Any other value will not signal prisignedness.

## PUBLISH-CDNSKEY, PUBLISH-CDS
Whether to publish CDNSKEY and/or CDS recording defined in [RFC 7344](https://tools.ietf.org/html/rfc7344).

To publish CDNSKEY records of the KSKs for the zone, set `PUBLISH-CDNSKEY` to `1`.

To publish CDS records for the KSKs in the zone, set `PUBLISH-CDS` to a comma-
separated list of [signature algorithm numbers](http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml#ds-rr-types-1).

This metadata can also be set using the [`pdnsutil`](dnssec.md#pdnsutil) options
`set-publish-cdnskey` and `set-publish-cds`. For an example for an RFC 7344
key rollover, see the [CDS and CDNSKEY howto](howtos.md#cds-dnskey-key-rollover).

## SOA-EDIT
When serving this zone, modify the SOA serial number in one of several ways.
Mostly useful to get slaves to re-transfer a zone regularly to get fresh RRSIGs.
See the [DNSSEC documentation](dnssec.md#soa-edit-ensure-signature-freshness-on-slaves)
for more information.

## TSIG-ALLOW-AXFR
Allow these named TSIG keys to AXFR this zone, see [Provisioning outbound AXFR access](tsig.md#provisioning-outbound-axfr-access).

## TSIG-ALLOW-DNSUPDATE
This setting allows you to set the TSIG key required to do an [DNS update](dnsupdate.md). If
[GSS-TSIG](tsig.md#gss-tsig) is enabled, you can put kerberos principals here as well.
