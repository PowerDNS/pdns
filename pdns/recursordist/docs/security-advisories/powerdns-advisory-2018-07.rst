PowerDNS Security Advisory 2018-07: Crafted query for meta-types can cause a denial of service
==============================================================================================

-  CVE: CVE-2018-14644
-  Date: November 6th 2018
-  Affects: PowerDNS Recursor from 4.0.0 up to and including 4.1.4
-  Not affected: 4.0.9, 4.1.5
-  Severity: Medium
-  Impact: Denial of service
-  Exploit: This problem can be triggered via crafted queries for some domains
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in PowerDNS Recursor where a remote attacker sending 
a DNS query for a meta-type like OPT can lead to a zone being wrongly cached
as failing DNSSEC validation. It only arises if the parent zone is signed, 
and all the authoritative servers for that parent zone answer with FORMERR to
a query for at least one of the meta-types.
As a result, subsequent queries from clients requesting DNSSEC validation
will be answered with a ServFail.

This issue has been assigned CVE-2018-14644 by Red Hat.

PowerDNS Recursor from 4.0.0 up to and including 4.1.4 is affected.

We would like to thank Toshifumi Sakaguchi for finding and subsequently
reporting this issue.
