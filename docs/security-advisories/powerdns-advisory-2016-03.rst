PowerDNS Security Advisory 2016-03: Denial of service via the web server
========================================================================

-  CVE: CVE-2016-7072
-  Date: December 15th 2016
-  Credit: Mongo
-  Affects: PowerDNS Authoritative Server up to and including 3.4.10,
   4.0.1
-  Not affected: PowerDNS Authoritative Server 3.4.11, 4.0.2
-  Severity: Medium
-  Impact: Degraded service or Denial of service
-  Exploit: This issue can be triggered by opening a large number of
   simultaneous connections to the web server
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: Disable the web server, or restrict access to it via a
   firewall.

An issue has been found in PowerDNS Authoritative Server allowing a
remote, unauthenticated attacker to cause a denial of service by opening
a large number of TCP connections to the web server. If the web server
runs out of file descriptors, it triggers an exception and terminates
the whole PowerDNS process. While it's more complicated for an
unauthorized attacker to make the web server run out of file descriptors
since its connection will be closed just after being accepted, it might
still be possible. This issue has been assigned CVE-2016-7072.

PowerDNS Authoritative Server up to and including 3.4.10 and 4.0.1 are
affected. The PowerDNS Recursor is not affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2016-03>`__

We would like to thank Mongo for finding and subsequently reporting this
issue.
