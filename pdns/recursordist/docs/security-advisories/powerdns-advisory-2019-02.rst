PowerDNS Security Advisory 2019-02: Insufficient validation of DNSSEC signatures
================================================================================

-  CVE: CVE-2019-3807
-  Date: 21st of January 2019
-  Affects: PowerDNS Recursor from 4.1.0 up to and including 4.1.8
-  Not affected: 4.0.x, 4.1.9
-  Severity: Medium
-  Impact: Insufficient validation
-  Exploit: This problem can be triggered via crafted responses
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in PowerDNS Recursor where records in the answer
section of responses received from authoritative servers with the AA flag
not set were not properly validated, allowing an attacker to bypass DNSSEC
validation.

This issue has been assigned CVE-2019-3807 by Red Hat.

PowerDNS Recursor from 4.1.0 up to and including 4.1.8 is affected.

We would like to thank Ralph Dolmans and George Thessalonikefs of NLNetLabs
for finding and subsequently reporting this issue!
