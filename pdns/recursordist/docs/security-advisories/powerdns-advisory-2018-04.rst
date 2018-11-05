PowerDNS Security Advisory 2018-04: Crafted answer can cause a denial of service
================================================================================

-  CVE: CVE-2018-10851
-  Date: November 6th 2018
-  Affects: PowerDNS Recursor from 3.2 up to and including 4.1.4
-  Not affected: 4.1.5, 4.0.9
-  Severity: Medium
-  Impact: Denial of service
-  Exploit: This problem can be triggered by an authoritative server
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: run the process inside a supervisor

An issue has been found in PowerDNS Recursor allowing a malicious
authoritative server to cause a memory leak by sending specially crafted
records.
The issue is due to the fact that some memory is allocated before the
parsing and is not always properly released if the record is malformed.

This issue has been assigned CVE-2018-10851.

When the PowerDNS Recursor is run inside a supervisor like supervisord
or systemd, an out-of-memory crash will lead to an automatic restart, limiting
the impact to a somewhat degraded service.

PowerDNS Recursor from 3.2 up to and including 4.1.4 is affected. Please
note that at the time of writing, PowerDNS Recursor 3.7 and below are no 
longer supported, as described in :doc:`../appendices/EOL`.
