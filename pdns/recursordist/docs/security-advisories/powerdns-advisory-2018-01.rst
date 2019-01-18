PowerDNS Security Advisory 2018-01: Insufficient validation of DNSSEC signatures
================================================================================

-  CVE: CVE-2018-1000003
-  Date: January 22nd 2018
-  Credit: CZ.NIC
-  Affects: PowerDNS Recursor 4.1.0
-  Not affected: PowerDNS Recursor < 4.1.0, 4.1.1
-  Severity: Low
-  Impact: Denial of existence spoofing
-  Exploit: This problem can be triggered by an attacker in position of
   man-in-the-middle
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in the DNSSEC validation component of PowerDNS Recursor,
allowing an ancestor delegation NSEC or NSEC3 record to be used to wrongfully
prove the non-existence of a RR below the owner name of that record. This would
allow an attacker in position of man-in-the-middle to send a NXDOMAIN answer
for a name that does exist. This issue has been assigned CVE-2018-1000003.

PowerDNS Recursor 4.1.0 is affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2018-01>`__

We would like to thank CZ.NIC for finding and subsequently reporting this
issue! Please also see https://lists.nic.cz/pipermail/knot-dns-users/2018-January/001309.html
