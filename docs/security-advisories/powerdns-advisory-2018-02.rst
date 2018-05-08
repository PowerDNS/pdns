PowerDNS Security Advisory 2018-02: Buffer overflow in dnsreplay
================================================================

-  CVE: CVE-2018-1046
-  Date: May 8th 2018
-  Credit: Wei Hao
-  Affects: dnsreplay from 4.0.0 up to and including 4.1.1
-  Not affected: dnsreplay 3.4.11, 4.1.2
-  Severity: High
-  Impact: Arbitrary code execution
-  Exploit: This problem can be triggered via a crafted PCAP file
-  Risk of system compromise: Yes
-  Solution: Upgrade to a non-affected version

An issue has been found in the dnsreplay tool provided with PowerDNS
Authoritative, where replaying a specially crafted PCAP file can trigger a
stack-based buffer overflow, leading to a crash and potentially arbitrary code
execution. This buffer overflow only occurs when the `--ecs-stamp` option of
dnsreplay is used. Regardless of this issue, the use of dnsreplay with
untrusted PCAP files is not advised.
This issue has been assigned CVE-2018-1046 by Red Hat.

PowerDNS Authoritative from 4.0.0 up to and including 4.1.1 is affected.

We would like to thank Wei Hao for finding and subsequently reporting
this issue.
