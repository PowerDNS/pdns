PowerDNS Security Advisory 2017-08: Crafted CNAME answer can cause a denial of service
======================================================================================

-  CVE: CVE-2017-15120
-  Date: December 11th 2017
-  Credit: Toshifumi Sakaguchi
-  Affects: PowerDNS Recursor from 4.0.0 up to and including 4.0.7
-  Not affected: PowerDNS Recursor 3.7.4, 4.0.8, 4.1.0
-  Severity: High
-  Impact:  Denial of service
-  Exploit: This problem can be triggered by an authoritative server
   sending a crafted CNAME answer with a class other than IN to the Recursor.
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: run the process inside a supervisor like supervisord or systemd

An issue has been found in the parsing of authoritative answers in PowerDNS
Recursor, leading to a NULL pointer dereference when parsing a specially crafted
answer containing a CNAME of a different class than IN.
This issue has been assigned CVE-2017-15120.

When the PowerDNS Recursor is run inside a supervisor like supervisord or
systemd, it will be automatically restarted, limiting the impact to somewhat
degraded service.

PowerDNS Recursor from 4.0.0 up to and including 4.0.7 are affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2017-08>`__

We would like to thank Toshifumi Sakaguchi for finding and subsequently
reporting this issue.
