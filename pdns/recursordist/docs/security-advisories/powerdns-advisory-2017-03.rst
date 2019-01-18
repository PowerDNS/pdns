PowerDNS Security Advisory 2017-03: Insufficient validation of DNSSEC signatures
================================================================================

-  CVE: CVE-2017-15090
-  Date: November 27th 2017
-  Credit: Kees Monshouwer
-  Affects: PowerDNS Recursor from 4.0.0 and up to and including 4.0.6
-  Not affected: PowerDNS Recursor < 4.0.0, 4.0.7
-  Severity: Medium
-  Impact: Records manipulation
-  Exploit: This problem can be triggered by an attacker in position of
   man-in-the-middle
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in the DNSSEC validation component of PowerDNS Recursor,
where the signatures might have been accepted as valid even if the signed data
was not in bailiwick of the DNSKEY used to sign it. This allows an attacker in
position of man-in-the-middle to alter the content of records by issuing a valid
signature for the crafted records. This issue has been assigned CVE-2017-15090.

PowerDNS Recursor from 4.0.0 up to and including 4.0.6 are affected.

For those unable to upgrade to a new version, a minimal patch is
`available <https://downloads.powerdns.com/patches/2017-03>`__

We would like to thank Kees Monshouwer for finding and subsequently reporting
this issue.
