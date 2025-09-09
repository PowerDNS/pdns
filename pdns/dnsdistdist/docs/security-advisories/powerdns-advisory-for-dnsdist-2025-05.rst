PowerDNS Security Advisory 2025-05 for DNSdist: Denial of service via crafted DoH exchange
==========================================================================================

- CVE: CVE-2025-30187
- Date: 2025-09-18T12:00:00+02:00
- Discovery date: 2025-08-26T00:00:00+02:00
- Affects: PowerDNS DNSdist from 1.9.0 to 1.9.10, 2.0.0
- Not affected: PowerDNS DNSdist 1.9.11, 2.0.1
- Severity: Low
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker crafting a DoH exchange
- Risk of system compromise: None
- Solution: Upgrade to patched version or use the h2o provider
- CWE: CWE-835
- CVSS: AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 2.0.0
- First fixed: 2.0.1
- Internal ID: 308

In some circumstances, when DNSdist is configured to use the nghttp2 library to process incoming DNS over HTTPS queries, an attacker might be able to cause a denial of service by crafting a DoH exchange that triggers an unbounded I/O read loop, causing an unexpected consumption of CPU resources.

`CVSS Score: 3.7 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to the patched version, or switch to the h2o provider.
