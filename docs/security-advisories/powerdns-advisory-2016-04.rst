PowerDNS Security Advisory 2016-04: Insufficient validation of TSIG signatures
==============================================================================

-  CVE: CVE-2016-7073 CVE-2016-7074
-  Date: December 15th 2016
-  Credit: Mongo
-  Affects: PowerDNS Authoritative Server up to and including 3.4.10,
   4.0.1, PowerDNS Recursor from 4.0.0 and up to and including 4.0.3
-  Not affected: PowerDNS Authoritative Server 3.4.11, 4.0.2, PowerDNS
   Recursor < 4.0.0, 4.0.4
-  Severity: Medium
-  Impact: Zone content alteration
-  Exploit: This problem can be triggered by an attacker in position of
   man-in-the-middle
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

Two issues have been found in PowerDNS Authoritative Server allowing an
attacker in position of man-in-the-middle to alter the content of an
AXFR because of insufficient validation of TSIG signatures. The first
issue is a missing check of the TSIG time and fudge values in
``AXFRRetriever``, leading to a possible replay attack. This issue has
been assigned CVE-2016-7073. The second issue is a missing check that
the TSIG record is the last one, leading to the possibility of parsing
records that are not covered by the TSIG signature. This issue has been
assigned CVE-2016-7074.

PowerDNS Authoritative Server up to and including 3.4.10 and 4.0.1 are
affected. PowerDNS Recursor from 4.0.0 up to and including 4.0.3 are
affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2016-04>`__

We would like to thank Mongo for finding and subsequently reporting this
issue.
