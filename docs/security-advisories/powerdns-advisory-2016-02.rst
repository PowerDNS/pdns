PowerDNS Security Advisory 2016-02: Crafted queries can cause abnormal CPU usage
================================================================================


-  CVE: CVE-2016-7068
-  Date: December 15th 2016
-  Credit: Florian Heinz and Martin Kluge
-  Affects: PowerDNS Authoritative Server up to and including 3.4.10,
   4.0.1, PowerDNS Recursor up to and including 3.7.3, 4.0.3
-  Not affected: PowerDNS Authoritative Server 3.4.11, 4.0.2 and
   PowerDNS Recursor 3.7.4, 4.0.4
-  Severity: Medium
-  Impact: Degraded service or Denial of service
-  Exploit: This issue can be triggered by sending specially crafted
   query packets
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: Run dnsdist with the rules provided below in front of
   potentially affected servers.

An issue has been found in PowerDNS allowing a remote, unauthenticated
attacker to cause an abnormal CPU usage load on the PowerDNS server by
sending crafted DNS queries, which might result in a partial denial of
service if the system becomes overloaded. This issue is based on the
fact that the PowerDNS server parses all records present in a query
regardless of whether they are needed or even legitimate. A specially
crafted query containing a large number of records can be used to take
advantage of that behaviour. This issue has been assigned CVE-2016-7068.

PowerDNS Authoritative Server up to and including 3.4.10 and 4.0.1 are
affected. PowerDNS Recursor up to and including 3.7.3 and 4.0.3 are
affected.

dnsdist can be used to block crafted queries, using
``RecordsCountRule()`` and ``RecordsTypeCountRule()`` to block queries
with crafted records.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2016-02>`__

We would like to thank Florian Heinz and Martin Kluge for finding and
subsequently reporting this issue.
