PowerDNS Security Advisory 2018-03: Crafted zone record can cause a denial of service
=====================================================================================

-  CVE: CVE-2018-10851
-  Date: November 6th 2018
-  Affects: PowerDNS Authoritative from 3.3.0 up to and including 4.1.4
-  Not affected: 4.1.5, 4.0.6
-  Severity: Medium
-  Impact: Denial of service
-  Exploit: This problem can be triggered via crafted records
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: run the process inside the guardian or inside a
   supervisor

An issue has been found in PowerDNS Authoritative Server allowing an
authorized user to cause a memory leak by inserting a specially crafted
record in a zone under their control, then sending a DNS query for that
record.
The issue is due to the fact that some memory is allocated before the
parsing and is not always properly released if the record is malformed.

This issue has been assigned CVE-2018-10851.

When the PowerDNS Authoritative Server is run inside the guardian
(``--guardian``), or inside a supervisor like supervisord or systemd, 
an out-of-memory crash will lead to an automatic restart, limiting the
impact to a somewhat degraded service.

PowerDNS Authoritative from 3.3.0 up to and including 4.1.4 is affected.
Please note that at the time of writing, PowerDNS Authoritative 3.4 and
below are no longer supported, as described in :doc:`../appendices/EOL`.
