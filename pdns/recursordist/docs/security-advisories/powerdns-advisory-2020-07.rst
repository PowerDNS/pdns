PowerDNS Security Advisory 2020-07: Cache pollution
===================================================

-  CVE: CVE-2020-25829
-  Date: 13th of October 2020
-  Affects: PowerDNS Recursor up to and including 4.3.4, 4.2.4 and 4.1.17
-  Not affected: 4.3.5, 4.2.5, 4.1.18
-  Severity: High
-  Impact: Denial of service
-  Exploit: This problem can be triggered by sending DNS queries
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: Filter ANY queries to prevent them from reaching the
   recursor.

An issue has been found in PowerDNS Recursor where a remote attacker
can cause the cached records for a given name to be updated to the
'Bogus' DNSSEC validation state, instead of their actual DNSSEC
'Secure' state, via a DNS ANY query. This results in a denial of
service for installations that always validate (dnssec=validate)
and for clients requesting validation when on-demand validation is
enabled (dnssec=process).
