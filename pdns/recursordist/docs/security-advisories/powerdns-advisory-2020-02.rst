PowerDNS Security Advisory 2020-02: Insufficient validation of DNSSEC signatures
================================================================================

-  CVE: CVE-2020-12244
-  Date: May 19th 2020
-  Affects: PowerDNS Recursor from 4.1.0 up to and including 4.3.0
-  Not affected: 4.3.1, 4.2.2, 4.1.16
-  Severity: Medium
-  Impact: Denial of existence spoofing
-  Exploit: This problem can be triggered by an attacker in position
   of man-in-the-middle
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: None

An issue has been found in PowerDNS Recursor 4.1.0 through 4.3.0 where
records in the answer section of a NXDOMAIN response lacking an SOA
were not properly validated in SyncRes::processAnswer. This would
allow an attacker in position of man-in-the-middle to send a NXDOMAIN
answer for a name that does exist, bypassing DNSSEC validation.

This issue has been assigned CVE-2020-12244.

PowerDNS Recursor from 4.1.0 up to and including 4.3.0 is affected.

Please note that at the time of writing, PowerDNS Authoritative 4.0 and
below are no longer supported, as described in
https://doc.powerdns.com/authoritative/appendices/EOL.html.

We would like to thank Matt Nordhoff for finding and subsequently
reporting this issue!

