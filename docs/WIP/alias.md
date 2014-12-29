# The ALIAS record

## Rationale
It is frequent practice to use CNAME records to direct Internet traffic, 
for example to a CDN. This works well for 'www.example.com', but it does not
work at the apex of a zone. Currently there are many ad-hoc solutions for this
problem. This document attempts to document the solution we chose, in hopes
that interoperability might be achieved.

## Semantics
The ALIAS record leads authoritative servers to synthesize A or AAAA records
in case these are not present.  The source of the synthesized A or AAAA
record is specified by the target of the ALIAS record.

ALIAS records, like wildcards, synthesize responses, and are not returned themselves
unless explicitly queried for. 

If a query comes in for the A or AAAA type of a label, but no such type is
matched, but there is an ALIAS type for that name, a server supporting the
ALIAS record will return A or AAAA records with addresses associated with the
target of the ALIAS.

Similarly, if an ANY query arrives for the name, all records from the local store
for that name are returned, plus the A and AAAA types associated with the ALIAS
record's target.

As an example:

```
$ORIGIN example.com
@		IN	SOA	ns1 ahu 2014091619 7200 3600 1209600 3600
@		IN	NS	ns1
@		IN	NS	ns2
www	IN	CNAME	xs.powerdns.com.
ns1	IN	A	1.2.3.4
ns2	IN	A	4.3.2.1
@		IN	ALIAS	www.powerdns.com.
@		IN	MX	25 outpost.ds9a.nl.
serv	IN	CNAME	@
```

A query for the A record of example.com has no match in the local store, but there
is an ALIAS record. In this case, the authoritative server synthesizes an A record
based on the IPv4 address of www.powerdns.com which was retrieved earlier.

The same applies, mutatis mutandis, for a query for the AAAA record of example.com.

It should be noted that if www.powerdns.com is itself a CNAME chain to A or
AAAA records, the data returned should be sourced from the eventual A and
AAAA records. The intermediate CNAMEs should not be returned.

A query for the A of serv.example.com gets normal CNAME processing, and then similarly
hits the ALIAS record, and returns the synthesized A record for example.com.

A query for the SRV record of example.com will return NODATA, since ALIAS records do
not synthesize to anything but A and AAAA records.

Finally, a query for ANY for example.com will return the SOA, NS and ALIAS records, 
in addition to any synthesized A and AAAA records matching the IPv4 and IPv6 addresses
of www.powerdns.com.

The TTL of the synthesized record is the minimum of the TTL on the ALIAS record and the TTL of
the origin IPv4 or IPv6 addresses. 

## NXDOMAIN and NODATA handling
If the server encounters a NODATA response when retrieving the target's IPv4 or IPv6 addresses,
a similar NODATA response should be synthesized, in other words, we pretend the ALIAS record 
was not even present.

For an NXDOMAIN response, no similar response is possible, since this would imply that the 
label does not exist, which it does because it has an ALIAS record. So an NXDOMAIN on the ALIAS 
target is presented just like the NODATA situation.

## Failures to lookup the ALIAS target
Any failures to lookup the ALIAS target's addresses lead to NODATA. 

## DNSSEC processing
If the zone is signed with DNSSEC, the synthesized records will need to be signed too, since
answers would otherwise be rejected as BOGUS.

An authoritative server is encouraged to perform DNSSEC validation when retrieving the IPv4
and IPv6 records associated with the target of the ALIAS record.

## Implementation details
Authoritative servers can either periodically refresh the ALIAS records, or they can look them
up and cache them as queries come in. 

In the PowerDNS implementation, a query with an ALIAS record inside is stored, and a query
is sent to a defined resolver to gather the A and/or AAAA records. Normal PowerDNS operations
then resume, until the resolver returns an answer, which is added to the stored packet, 
which is then returned to the original requestor. The result is also cached.

Other implementations might employ periodic 'flattening' to achieve the same effect statically.

## AXFR of ALIAS records
ALIAS records are AXFRed without further processing, where it should be noted that
this only makes sense if the retrieving server is also capable of doing ALIAS processing.

## EDNS Subnet
Authoritative servers sometimes give out different answers based on the IP
address of the resolver asking.  As a further refinement, some resolvers can
pass along (part) of the actual stub-resolver asking the question, and base
its answer on that 'real' address. 

For ALIAS processing, implementors are encouraged to pass along or use all
knowledge of the remote client IP address when retrieving A or AAAA records.

## Resolver processing
Resolvers are not expected to perform processing on ALIAS records. In fact, except when
querying for ALIAS records directly, or doing an ANY lookup, in normal operations,
resolver will never see ALIAS records. Compare to the handling of wildcards, which are also
not expanded by resolvers.
