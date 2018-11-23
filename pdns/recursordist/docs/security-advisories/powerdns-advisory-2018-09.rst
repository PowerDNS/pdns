PowerDNS Security Advisory 2018-09: Crafted query can cause a denial of service
===============================================================================

-  CVE: CVE-2018-16855
-  Date: 26th of November 2018
-  Affects: PowerDNS Recursor from 4.1.0 up to and including 4.1.7
-  Not affected: 4.0.x, 4.1.8
-  Severity: Medium
-  Impact: Denial of service
-  Exploit: This problem can be triggered via crafted queries
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in PowerDNS Recursor where a remote attacker sending
a DNS query can trigger an out-of-bounds memory read while computing the hash
of the query for a packet cache lookup, possibly leading to a crash.

This issue has been assigned CVE-2018-16855 by Red Hat.

When the PowerDNS Recursor is run inside a supervisor like supervisord
or systemd, an out-of-memory crash will lead to an automatic restart, limiting
the impact to a somewhat degraded service.

PowerDNS Recursor from 4.1.0 up to and including 4.1.7 is affected.
