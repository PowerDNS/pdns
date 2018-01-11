PowerDNS Security Advisory 2017-05: Cross-Site Scripting in the web interface
=============================================================================

-  CVE: CVE-2017-15092
-  Date: November 27th 2017
-  Credit: Nixu, Chris Navarrete of Fortinet's Fortiguard Labs
-  Affects: PowerDNS Recursor from 4.0.0 up to and including 4.0.6
-  Not affected: PowerDNS Recursor 4.0.7, 3.7.x
-  Severity: Medium
-  Impact: Alteration and denial of service of the web interface
-  Exploit: This problem can be triggered by an attacker sending DNS queries
   to the server
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in the web interface of PowerDNS Recursor, where the
qname of DNS queries was displayed without any escaping, allowing a remote
attacker to inject HTML and Javascript code into the web interface, altering
the content. This issue has been assigned CVE-2017-15092.

PowerDNS Recursor from 4.0.0 up to and including 4.0.6 are affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2017-05>`__

We would like to thank Nixu and Chris Navarrete of Fortinet's Fortiguard Labs
for independently finding and reporting this issue.
