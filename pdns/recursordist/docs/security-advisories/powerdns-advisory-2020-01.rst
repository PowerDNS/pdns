PowerDNS Security Advisory 2020-01: Denial of Service
=====================================================

-  CVE: CVE-2020-10995
-  Date: May 19th 2020
-  Affects: PowerDNS Recursor from 4.1.0 up to and including 4.3.0
-  Not affected: 4.1.16, 4.2.2, 4.3.1
-  Severity: Medium
-  Impact: Degraded Service
-  Exploit: This problem can be triggered via a crafted reply
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: None

An issue in the DNS protocol has been found that allow malicious
parties to use recursive DNS services to attack third party
authoritative name servers. The attack uses a crafted reply by an
authoritative name server to amplify the resulting traffic between the
recursive and other authoritative name servers.  Both types of service
can suffer degraded performance as an effect.

This issue has been assigned CVE-2020-10995.

PowerDNS Recursor from 4.1.0 up to and including 4.3.0 is
affected. PowerDNS Recursor 4.1.16, 4.2.2 and 4.3.1 contain a
mitigation to limit the impact of this DNS protocol issue.

Please note that at the time of writing, PowerDNS Recursor 4.0 and
below are no longer supported, as described in
https://doc.powerdns.com/recursor/appendices/EOL.html.

We would like to thank Lior Shafir, Yehuda Afek and Anat Bremler-Barr
for finding and subsequently reporting this issue!
