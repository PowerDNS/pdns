PowerDNS Security Advisory 2018-06: Packet cache pollution via crafted query
============================================================================

-  CVE: CVE-2018-14626
-  Date: November 6th 2018
-  Affects: PowerDNS Recursor from 4.0.0 up to and including 4.1.4
-  Not affected: 4.1.5, 4.0.9
-  Severity: Medium
-  Impact: Denial of service
-  Exploit: This problem can be triggered via crafted queries
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in PowerDNS Recursor allowing a remote user to craft
a DNS query that will cause an answer without DNSSEC records to be inserted
into the packet cache and be returned to clients asking for DNSSEC records,
thus hiding the presence of DNSSEC signatures for a specific qname and qtype.
For a DNSSEC-signed domain, this means that clients performing DNSSEC validation
by themselves might consider the answer to be bogus until it expires from the packet
cache, leading to a denial of service.

This issue has been assigned CVE-2018-14626.

PowerDNS Recursor from 4.0.0 up to and including 4.1.4 is affected.

We would like to thank Kees Monshouwer for finding and subsequently reporting
this issue.
