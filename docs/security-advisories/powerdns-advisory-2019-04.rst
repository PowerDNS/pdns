PowerDNS Security Advisory 2019-04: Denial of service via crafted zone records
==============================================================================

-  CVE: CVE-2019-10162
-  Date: June 21st 2019
-  Affects: PowerDNS Authoritative up to and including 4.1.9
-  Not affected: 4.1.10, 4.0.8
-  Severity: Medium
-  Impact: Denial of Service
-  Exploit: This problem can be triggered via crafted records
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: run the process inside the guardian or inside a supervisor

An issue has been found in PowerDNS Authoritative Server allowing an
authorized user to cause the server to exit by inserting a crafted
record in a MASTER type zone under their control. The issue is due
to the fact that the Authoritative Server will exit when it runs into a
parsing error while looking up the NS/A/AAAA records it is about to
use for an outgoing notify.

This issue has been assigned CVE-2019-10162.

PowerDNS Authoritative up to and including 4.1.9 is affected.
Please note that at the time of writing, PowerDNS Authoritative 3.4 and
below are no longer supported, as described in
https://doc.powerdns.com/authoritative/appendices/EOL.html.

We would like to thank Gert van Dijk for finding and subsequently
reporting this issue!
