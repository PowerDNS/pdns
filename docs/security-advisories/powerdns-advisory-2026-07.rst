PowerDNS Security Advisory 2026-07: Insufficient input validation of internal web server
========================================================================================

- CVE: CVE-2026-42005
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-25T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 3.4.0 up to and including 4.9.15, 5.0.5 and 5.1.1
- Not affected: PowerDNS Authoritative Server 4.9.16, 5.0.6 and 5.1.2
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by a client sending crafted HTTP queries, but only if the internal webserver is enabled.
- Risk of system compromise: None
- Solution: Upgrade to patched version or do not enable the internal webserver
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L
- Last affected: 4.9.15,5.0.5,5.1.1
- First fixed: 4.9.16,5.0.6,5.1.2
- Internal ID: 481

An attacker can send a web request that causes unlimited memory allocation in the internal web server, leading to a denial of service. The internal web server is disabled by default.

`CVSS Score: 4.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version, or prevent network access to the internal webserver. In general for defense in-depth reasons we recommend making the internal web server only accessible to trusted clients.

We would like to thank ilya rozentsvaig for bringing this issue to our attention.
