# Per zone settings aka Domain Metadata
Starting with the PowerDNS Authoritative Server 3.0, each served zone can have "metadata". Such metadata determines how this zone behaves in certain circumstances.

**Warning**: Domain metadata is only available for DNSSEC capable backends! Make sure to enable the proper '-dnssec' setting to benefit, and to have performed the DNSSEC schema update.

## ALLOW-AXFR-FROM
Starting with the PowerDNS Authoritative Server 3.1, per-zone AXFR ACLs can be stored in the domainmetadata table.

Each ACL row can list one subnet (v4 or v6), or the magical value 'AUTO-NS' that tries to allow all potential slaves in.

Example:

```
sql> select id from domains where name='example.com';
7
sql> insert into domainmetadata (domain_id, kind, content) values (7,'ALLOW-AXFR-FROM','AUTO-NS');
sql> insert into domainmetadata (domain_id, kind, content) values (7,'ALLOW-AXFR-FROM','2001:db8::/48');
```

## AXFR-SOURCE
The IP address to use as a source address for sending AXFR requests.

## ALLOW-DNSUPDATE-FROM, TSIG-ALLOW-DNSUPDATE, FORWARD-DNSUPDATE, SOA-EDIT-DNSUPDATE
See the documentation on [Dynamic DNS update](dnsupdate.md)

## ALSO-NOTIFY
When notifying this domain, also notify this nameserver (can occur multiple times).

## AXFR-MASTER-TSIG
Use this named TSIG key to retrieve this zone from its master (see [Provisioning signed notification and AXFR requests](modes-of-operation.md#provisioning-signed-notification-and-axfr-requests)).

## GSS-ALLOW-AXFR-PRINCIPAL
Allow this GSS principal to perform AXFR retrieval. Most commonly it is host/something@REALM, DNS/something@REALM or user@REALM. (See [GSS-TSIG support](gss-tsig.md)).

## GSS-ACCEPTOR-PRINCIPAL
Use this principal for accepting GSS context. (See [GSS-TSIG support](gss-tsig.md)).

## LUA-AXFR-SCRIPT
Script to be used to edit incoming AXFRs, see [Modifying a slave zone using a script](modes-of-operation.md#modifying-a-slave-zone-using-a-script).

## NSEC3NARROW
Set to "1" to tell PowerDNS this zone operates in NSEC3 'narrow' mode. See `set-nsec3` for [`pdnssec`](dnssec.md#pdnssec).

## NSEC3PARAM
NSEC3 parameters of a DNSSEC zone. Will be used to synthesize the NSEC3PARAM record. If present, NSEC3 is used, if not present, zones default to NSEC. See `set-nsec3` in [`pdnssec`](dnssec.md#pdnssec). Example content: "1 0 1 ab".

## PRESIGNED
This zone carries DNSSEC RRSIGs (signatures), and is presigned. PowerDNS sets this flag automatically upon incoming zone transfers (AXFR) if it detects DNSSEC records in the zone. However, if you import a presigned zone using `zone2sql` or `pdnssec load-zone` you must explicitly set the zone to be `PRESIGNED`. Note that PowerDNS will not be able to correctly serve the zone if the imported data is bogus or incomplete. Also see `set-presigned` in [`pdnssec`](dnssec.md#pdnssec).

## SOA-EDIT
When serving this zone, modify the SOA serial number in one of several ways. Mostly useful to get slaves to re-transfer a zone regularly to get fresh RRSIGs.

Inception refers to the time the RRSIGs got updated in [live-signing mode](dnssec.md#records-keys-signatures-hashes-within-powerdnssec-in-online-signing-mode). This happens every week (see [Signatures](dnssec.md#signatures)). The inception time does not depend on local timezone, but some modes below will use localtime for representation.

Available modes are:

* INCREMENT-WEEKS: Increments the serial with the number of weeks since the epoch. This should work in every setup; but the result won't look like YYYYMMDDSS anymore.
* INCEPTION-EPOCH (available since 3.1): Sets the new SOA serial number to the maximum of the old SOA serial number, and age in seconds of the last inception. This requires your backend zone to use age in seconds as SOA serial. The result is still the age in seconds of the last change.
* INCEPTION-INCREMENT (available since 3.3): Uses YYYYMMDDSS format for SOA serial numbers. If the SOA serial from the backend is within two days after inception, it gets incremented by two (the backend should keep SS below 98). Otherwise it uses the maximum of the backend SOA serial number and inception time in YYYYMMDD01 format. This requires your backend zone to use YYYYMMDDSS as SOA serial format. Uses localtime to find the day for inception time.
* INCEPTION (not recommended): Sets the SOA serial to the last inception time in YYYYMMDD01 format. Uses localtime to find the day for inception time. **Warning**: The SOA serial will only change on inception day, so changes to the zone will get visible on slaves only on the following inception day.
* INCEPTION-WEEK (not recommended): Sets the SOA serial to the number of weeks since the epoch, which is the last inception time in weeks. **Warning**: Same problem as INCEPTION
* EPOCH: Sets the SOA serial to the number of seconds since the epoch. **Warning**: Don't combine this with AXFR - the slaves would keep refreshing all the time. If you need fast updates, sync the backend databases directly with incremental updates (or use the same database server on the slaves)

## TSIG-ALLOW-AXFR
Allow these named TSIG keys to AXFR this zone (see [Provisioning outbound AXFR access](modes-of-operation.md#provisioning-outbound-axfr-access)).

## TSIG-ALLOW-DNSUPDATE
This setting allows you to set the TSIG key required to do an DNS update. If GSS-TSIG is enabled, you can put kerberos principals here as well.
