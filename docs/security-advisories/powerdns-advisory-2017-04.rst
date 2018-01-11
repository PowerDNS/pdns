PowerDNS Security Advisory 2017-04: Missing check on API operations
===================================================================

-  CVE: CVE-2017-15091
-  Date: November 27th 2017
-  Credit: everyman
-  Affects: PowerDNS Authoritative up to and including 4.0.4, 3.4.11
-  Not affected: PowerDNS Authoritative 4.0.5
-  Severity: Low
-  Impact:  Denial of service
-  Exploit: This problem can be triggered by an attacker with valid
   API credentials
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in the API component of PowerDNS Authoritative,
where some operations that have an impact on the state of the server
are still allowed even though the API has been configured as read-only
via the
`api-readonly <https://docs.powerdns.com/authoritative/settings.html#api-readonly>`__
keyword.
This missing check allows an attacker with valid API credentials to flush
the cache, trigger a zone transfer or send a NOTIFY. This issue has been
assigned CVE-2017-15091.

PowerDNS Authoritative up to and including 4.0.4 and 3.4.11 are affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2017-04>`__

We would like to thank everyman for finding and subsequently reporting
this issue.
