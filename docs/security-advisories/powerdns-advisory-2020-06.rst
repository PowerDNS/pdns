PowerDNS Security Advisory 2020-06: Various issues in our GSS-TSIG support
==========================================================================

-  CVE: CVE-2020-24696, CVE-2020-24697, CVE-2020-24698
-  Date: September 22nd, 2020
-  Affects: PowerDNS Authoritative versions before 4.4.0, when compiled with --enable-experimental-gss-tsig
-  Not affected: 4.4.0 and up, and any version compiled without GSS-TSIG support
-  Severity: Low
-  Impact: Crashes, Information Leaks, Possible code execution
-  Exploit: This problem can be triggered via crafted packets
-  Risk of system compromise: Low
-  Solution: Do not use software built with GSS-TSIG support

Various issues have been found in our GSS-TSIG support, where an unauthorized attacker could cause crashes, possibly leak uninitialised memory, and possibly execute arbitrary code.

These issues have been assigned:

* CVE-2020-24696: A remote, unauthenticated attacker can trigger a race condition leading to a crash, or possibly arbitrary code execution, by sending crafted queries with a GSS-TSIG signature.
* CVE-2020-24697: A remote, unauthenticated attacker can cause a denial of service by sending crafted queries with a GSS-TSIG signature.
* CVE-2020-24698: A remote, unauthenticated attacker might be able to cause a double-free, leading to a crash or possibly arbitrary code execution by sending crafted queries with a GSS-TSIG signature.

All PowerDNS Authoritative versions are affected, but *only* if they have been compiled with ``--enable-experimental-gss-tsig``.
We have never published packages with the feature enabled.

Because of the various issues with the feature (including a complete lack of testing code around it), and no reports of production usage of GSS-TSIG, we have decided to remove the relevant code completely in PowerDNS Authoritative 4.4.0.
Users of earlier versions that rely on the feature can keep doing so until they upgrade to 4.4.0, but need to be aware of these issues.

We would like to thank Nathaniel Ferguson for finding and subsequently reporting these issues!
