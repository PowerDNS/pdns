PowerDNS Security Advisory for dnsdist 2018-08: Record smuggling when adding ECS or XPF
=======================================================================================

-  CVE: CVE-2018-14663
-  Date: November 8th 2018
-  Affects: PowerDNS DNSDist up to and including 1.3.2
-  Not affected: 1.3.3
-  Severity: Low
-  Impact: Insufficient validation
-  Exploit: This problem can be triggered via crafted queries
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in PowerDNS DNSDist allowing a remote attacker to craft a DNS query with trailing data such that the addition of a record by dnsdist, for example an OPT record when adding EDNS Client Subnet, might result in the trailing data being smuggled to the backend as a valid record while not seen by dnsdist.
This is an issue when dnsdist is deployed as a DNS Firewall and used to filter some records that should not be received by the backend.
This issue occurs only when either the 'useClientSubnet' or the experimental 'addXPF' parameters are used when declaring a new backend.

This issue has been assigned CVE-2018-14663 by Red Hat.

PowerDNS DNSDist up to and including 1.3.2 is affected.

We would like to thank Richard Gibson for finding and subsequently reporting this issue.
