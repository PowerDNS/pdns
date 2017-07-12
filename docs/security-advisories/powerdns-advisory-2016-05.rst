PowerDNS Security Advisory 2016-05: Crafted zone record can cause a denial of service
=====================================================================================

-  CVE: CVE-2016-2120
-  Date: December 15th 2016
-  Credit: Mathieu Lafon
-  Affects: PowerDNS Authoritative Server up to and including 3.4.10,
   4.0.1
-  Not affected: PowerDNS Authoritative Server 3.4.11, 4.0.2
-  Severity: Medium
-  Impact: Denial of service
-  Exploit: This issue can be triggered by inserting a specially crafted
   record in a zone
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in PowerDNS Authoritative Server allowing an
authorized user to crash the server by inserting a specially crafted
record in a zone under their control then sending a DNS query for that
record. The issue is due to an integer overflow when checking if the
content of the record matches the expected size, allowing an attacker to
cause a read past the buffer boundary. This issue has been assigned
CVE-2016-2120.

PowerDNS Authoritative Server up to and including 3.4.10 and 4.0.1 are
affected. The PowerDNS Recursor is not affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2016-05>`__

We would like to thank Mathieu Lafon for finding and subsequently
reporting this issue.
