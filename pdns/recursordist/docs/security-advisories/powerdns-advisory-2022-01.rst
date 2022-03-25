PowerDNS Security Advisory 2022-01: incomplete validation of incoming IXFR transfer in Authoritative Server and Recursor
========================================================================================================================

- CVE: CVE-2022-27227
- Date: 25th of March 2022.
- Affects: PowerDNS Authoritative version 4.4.2, 4.5.3, 4.6.0 and PowerDNS Recursor 4.4.7, 4.5.7 and 4.6.0
- Not affected: PowerDNS Authoritative Server 4.4.3, 4.5.4, 4.6.1 and PowerDNS Recursor 4.4.8, 4.5.8 and 4.6.1
- Severity: Low
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker controlling the network path for IXFR transfers
- Risk of system compromise: None
- Solution: Upgrade to patched version, do not use IXFR in Authoritative Server

- In the Authoritative server this issue only applies to secondary zones for which IXFR transfers have been enabled and the network path to the primary server is not trusted. Note that IXFR transfers are not enabled by default.
-  In the Recursor it applies to setups retrieving one or more RPZ zones from a remote server if the network path to the server is not trusted.

IXFR usually exchanges only the modifications between two versions of a zone, but sometimes needs to fall back to a full transfer of the current version.
When IXFR falls back to a full zone transfer, an attacker in position of man-in-the-middle can cause the transfer to be prematurely interrupted. This interrupted transfer is mistakenly interpreted as a complete transfer, causing an incomplete zone to be processed.
For the Authoritative Server, IXFR transfers are not enabled by default.
The Recursor only uses IXFR for retrieving RPZ zones. An incomplete RPZ transfer results in missing policy entries, potentially causing some DNS names and IP addresses to not be properly intercepted.

We would like to thank Nicolas Dehaine and Dmitry Shabanov from ThreatSTOP for reporting and initial analysis of this issue.
