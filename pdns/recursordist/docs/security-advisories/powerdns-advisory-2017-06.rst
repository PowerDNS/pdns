PowerDNS Security Advisory 2017-06: Configuration file injection in the API
===========================================================================

-  CVE: CVE-2017-15093
-  Date: November 27th 2017
-  Credit: Nixu
-  Affects: PowerDNS Recursor up to and including 4.0.6, 3.7.4
-  Not affected: PowerDNS Recursor 4.0.7
-  Severity: Medium
-  Impact: Alteration of configuration by an API user
-  Exploit: This problem can be triggered by an attacker with valid API
   credentials
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: Disable the ability to alter the configuration via the API
   by setting `api-config-dir` to an empty value (default), or set the API
   read-only via the `api-readonly` setting.

An issue has been found in the API of PowerDNS Recursor during a source code
audit by Nixu. When `api-config-dir` is set to a non-empty value, which is not
the case by default, the API allows an authorized user to update the Recursor's
ACL by adding and removing netmasks, and to configure forward zones. It was
discovered that the new netmask and IP addresses of forwarded zones were not
sufficiently validated, allowing an authenticated user to inject new
configuration directives into the Recursor's configuration. This issue has been
assigned CVE-2017-15093.

PowerDNS Recursor up to and including 4.0.6 and 3.7.4 are affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2017-06>`__

We would like to thank Nixu for finding and subsequently reporting this issue.
