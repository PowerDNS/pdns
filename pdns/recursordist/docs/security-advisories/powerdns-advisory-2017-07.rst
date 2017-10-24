PowerDNS Security Advisory 2017-07: Memory leak in DNSSEC parsing
=================================================================

-  CVE: CVE-2017-15094
-  Date: November 27th 2017
-  Credit: Nixu
-  Affects: PowerDNS Recursor from 4.0.0 up to and including 4.0.6
-  Not affected: PowerDNS Recursor 4.0.7
-  Severity: Medium
-  Impact:  Denial of service
-  Exploit: This problem can be triggered by an authoritative server
   sending crafted ECDSA DNSSEC keys to the Recursor.
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: Disable DNSSEC validation by setting the `dnssec` parameter
   to `off` or `process-no-validate` (default).

An issue has been found in the DNSSEC parsing code of PowerDNS Recursor during
a code audit by Nixu, leading to a memory leak when parsing specially crafted
DNSSEC ECDSA keys. These keys are only parsed when validation is enabled by
setting `dnssec` to a value other than `off` or `process-no-validate` (default).
This issue has been assigned CVE-2017-15094.

PowerDNS Recursor from 4.0.0 up to and including 4.0.6 are affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2017-07>`__

We would like to thank Nixu for finding and subsequently reporting
this issue.
