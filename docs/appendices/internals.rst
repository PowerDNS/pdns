Internals
=========

How PowerDNS translates DNS queries into backend queries
--------------------------------------------------------

A DNS query is not a straightforward lookup. Many DNS queries need to
check the backend for additional data, for example to determine if an
unfound record should lead to an NXDOMAIN ('we know about this domain,
but that record does not exist') or an unauthoritative response.

Simplified, without CNAME processing, wildcards, referrals and DNSSEC,
the algorithm is like this:

When a query for a ``qname``/``qtype`` tuple comes in, PowerDNS queries
backends to find the closest matching SOA, thus figuring out what
backend owns this zone. When the right backend has been found, PowerDNS
issues a ``qname``/``ANY`` query to the backend. If the response is
empty, NXDOMAIN is concluded. If the response is not empty, any contents
matching the original qtype are added to the list of records to return,
and NOERROR is set.

Each of these records is now investigated to see if it needs 'additional
processing'. This holds for example for MX records which may point to
hosts for which the PowerDNS backends also contain data. This involves
further lookups for A or AAAA records.

After all additional processing has been performed, PowerDNS sieves out
all double records which may well have appeared. The resulting set of
records is added to the answer packet, and sent out.

A zone transfer works by looking up the ``domain_id`` of the SOA record
of the name and then listing all records of that ``domain_id``. This is
why all records in a domain need to have the same domain\_id.

If no SOA was found, a REFUSED is returned.

