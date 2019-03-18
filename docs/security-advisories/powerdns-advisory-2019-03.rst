PowerDNS Security Advisory 2019-03: Insufficient validation in the HTTP remote backend
======================================================================================

-  CVE: CVE-2019-3871
-  Date: March 18th 2019
-  Affects: PowerDNS Authoritative up to and including 4.1.6
-  Not affected: 4.1.7, 4.0.7
-  Severity: High
-  Impact: Denial of Service, Information Disclosure, Content spoofing
-  Exploit: This problem can be triggered via crafted queries
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version

An issue has been found in PowerDNS Authoritative Server when the
HTTP remote backend is used in RESTful mode (without post=1 set),
allowing a remote user to cause the HTTP backend to connect to
an attacker-specified host instead of the configured one, via a
crafted DNS query.
This can be used to cause a denial of service by preventing the remote
backend from getting a response, content spoofing if the attacker can
time its own query so that subsequent queries will use an attacker-controlled
HTTP server instead of the configured one, and possibly information
disclosure if the Authoritative Server has access to internal servers.

This issue has been assigned CVE-2019-3871.

PowerDNS Authoritative up to and including 4.1.6 is affected.
Please note that at the time of writing, PowerDNS Authoritative 3.4 and
below are no longer supported, as described in 
https://doc.powerdns.com/authoritative/appendices/EOL.html.

We would like to thank Adam Dobrawy, Frederico Silva and Gregory
Brzeski from HyperOne.com for finding and subsequently reporting 
this issue!
