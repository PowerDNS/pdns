PowerDNS Security Advisory 2025-03 for DNSdist: Denial of service via crafted TCP exchange
==========================================================================================

- CVE: CVE-2025-30193
- Date: 2025-05-20T13:00:00+02:00
- Discovery date: 2025-05-13T11:13:00+02:00
- Affects: PowerDNS DNSdist up to 1.9.9
- Not affected: PowerDNS DNSdist 1.9.10
- Severity: High
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker crafting a TCP exchange
- Risk of system compromise: None
- Solution: Upgrade to patched version or restrict the maximum number of queries on a single incoming TCP connection
- CWE: CWE-674
- CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 1.9.9
- First fixed: 1.9.10
- Internal ID: 299

In some circumstances, when DNSdist is configured to allow an unlimited number of queries on a single, incoming TCP connection from a client, an attacker can cause a denial of service by crafting a TCP exchange that triggers an exhaustion of the stack and a crash of DNSdist, causing a denial of service.

`CVSS Score: 7.5 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1>`__

The remedy is: upgrade to the patched 1.9.10 version

A workaround is to restrict the maximum number of queries on incoming TCP connections to a safe value, like 50, via the :func:`setMaxTCPQueriesPerConnection` setting.

We would like to thank Renaud Allard for bringing this issue to our attention.