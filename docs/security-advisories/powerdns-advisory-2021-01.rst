PowerDNS Security Advisory 2021-01: Specific query crashes Authoritative Server
===============================================================================

-  CVE: CVE-2021-36754
-  Date: July 26th, 2021
-  Affects: PowerDNS Authoritative version 4.5.0
-  Not affected: 4.4.x and below, 4.5.1
-  Severity: High
-  Impact: Denial of service
-  Exploit: This problem can be triggered via a specific query packet
-  Risk of system compromise: None
-  Solution: Upgrade to 4.5.1, or filter queries in ``dnsdist``

PowerDNS Authoritative Server 4.5.0 (and the alpha/beta/rc1/rc2 prereleases that came before it) will crash with an uncaught out of bounds exception if it receives a query with QTYPE 65535. The offending code was not present in earlier versions, and they are not affected.

Users that cannot upgrade immediately, but do have dnsdist in place, can use dnsdist to filter such queries before they do harm, with something like ``addAction(QTypeRule(65535), RCodeAction(DNSRCode.REFUSED))``.

When the PowerDNS Authoritative Server is run inside a supervisor like supervisord or systemd, an uncaught exception crash will lead to an automatic restart, limiting the impact to a somewhat degraded service.

We would like to thank Reinier Schoof and Robin Geuze of TransIP for noticing crashes in production, immediately letting us know, and helping us figure out what was happening.
