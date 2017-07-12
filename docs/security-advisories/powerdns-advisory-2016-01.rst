PowerDNS Security Advisory 2016-01: Crafted queries can cause unexpected backend load
-------------------------------------------------------------------------------------

-  CVE: CVE-2016-5426, CVE-2016-5427
-  Date: 9th of September 2016
-  Credit: Florian Heinz and Martin Kluge
-  Affects: PowerDNS Authoritative Server up to and including 3.4.9
-  Not affected: PowerDNS Authoritative Server 3.4.10, 4.x
-  Severity: Medium
-  Impact: Degraded service or Denial of service
-  Exploit: This problem can be triggered by sending specially crafted
   query packets
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: Run dnsdist with the rules provided below in front of
   potentially affected servers, or dimension the backend capacity so
   that it can handle the increased load.

Two issues have been found in PowerDNS Authoritative Server allowing a
remote, unauthenticated attacker to cause an abnormal load on the
PowerDNS backend by sending crafted DNS queries, which might result in a
partial denial of service if the backend becomes overloaded. SQL
backends for example are particularly vulnerable to this kind of
unexpected load if they have not been dimensioned for it. The first
issue is based on the fact that PowerDNS Authoritative Server accepts
queries with a qname's length larger than 255 bytes. This issue has been
assigned CVE-2016-5426. The second issue is based on the fact that
PowerDNS Authoritative Server does not properly handle dot inside
labels. This issue has been assigned CVE-2016-5427. Both issues have
been addressed by this
`commit <https://github.com/PowerDNS/pdns/commit/881b5b03a590198d03008e4200dd00cc537712f3>`__.

PowerDNS Authoritative Server up to and including 3.4.9 is affected. No
other versions are affected. The PowerDNS Recursor is not affected.

dnsdist can be used to block crafted queries, using
QNameWireLengthRule() to block queries with a qname larger than 255
bytes and QNameLabelsCountRule() to block queries with a very large
amount of labels. Please note that restricting the number of labels in a
query might lead to unexpected issues, especially with DNSSEC-enabled
domains.

We'd like to thank Florian Heinz and Martin Kluge for finding and
subsequently reporting this issue.
