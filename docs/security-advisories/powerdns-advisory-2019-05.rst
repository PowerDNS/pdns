PowerDNS Security Advisory 2019-05: Denial of service via NOTIFY packets
========================================================================

-  CVE: CVE-2019-10163
-  Date: June 21st 2019
-  Affects: PowerDNS Authoritative up to and including 4.1.8
-  Not affected: 4.1.9, 4.0.8
-  Severity: Medium
-  Impact: Denial of Service
-  Exploit: This problem can be triggered via the sending of NOTIFY
   packets from an authorized master
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in PowerDNS Authoritative Server allowing a
remote, authorized master server to cause a high CPU load or
even prevent any further updates to any slave zone by sending a
large number of NOTIFY messages.
Note that only servers configured as slaves are affected by this issue.

This issue has been assigned CVE-2019-10163.

PowerDNS Authoritative up to and including 4.1.8 is affected.
Please note that at the time of writing, PowerDNS Authoritative 3.4 and
below are no longer supported, as described in
https://doc.powerdns.com/authoritative/appendices/EOL.html.

We would like to thank George Asenov for finding and subsequently
reporting this issue!
