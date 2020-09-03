PowerDNS Security Advisory 2020-05: Leaking uninitialised memory through crafted zone records
=============================================================================================

-  CVE: CVE-2020-17482
-  Date: September 22nd, 2020
-  Affects: PowerDNS Authoritative 4.3.0 and earlier
-  Not affected: 4.3.1 and up, 4.2.3 and up, 4.1.14 and up
-  Severity: Low
-  Impact: Information leak
-  Exploit: This problem can be triggered via crafted records by an authorized user
-  Risk of system compromise: Low
-  Solution: Upgrade to a fixed version
-  Workaround: Do not take zone data from untrusted users

An issue has been found in PowerDNS Authoritative Server before 4.3.1 where an authorized user with the ability to insert crafted records into a zone might be able to leak the content of uninitialized memory.
Such a user could be a customer inserting data via a control panel, or somebody with access to the REST API.
Crafted records cannot be inserted via AXFR.

This issue has been assigned CVE-2020-17482.

PowerDNS Authoritative up to and including version 4.3.0 are affected.
Please note that at the time of writing, PowerDNS Authoritative 4.0 and below are no longer supported, as described in
https://doc.powerdns.com/authoritative/appendices/EOL.html.

We would like to thank Nathaniel Ferguson for finding and subsequently reporting this issue!
