PowerDNS Security Advisory 2025-02 for DNSdist: Denial of service via crafted DoH exchange
==========================================================================================

- CVE: CVE-2025-30194
- Date: 2025-04-29T12:00:00+02:00
- Discovery date: 2025-04-25T21:55:00+02:00
- Affects: PowerDNS DNSdist from 1.9.0 up to 1.9.8
- Not affected: PowerDNS DNSdist 1.9.9 and versions before 1.9.0
- Severity: High
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker crafting a DoH exchange
- Risk of system compromise: None
- Solution: Upgrade to patched version or temporarily switch to the h2o provider
- CWE: CWE-416
- CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 1.9.8
- First fixed: 1.9.9
- Internal ID: 297

When DNSdist is configured to provide DoH via the nghttp2 provider, an attacker can cause a denial of service by crafting a DoH exchange that triggers an illegal memory access (double-free) and crash of DNSdist, causing a denial of service.

`CVSS Score: 7.5 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1>`__, only for configurations where incoming DoH is enabled via the nghttp2 provider.

The remedy is: upgrade to the patched 1.9.9 version.

A workaround is to temporarily switch to the h2o provider until DNSdist has been upgraded to a fixed version.

We would like to thank Charles Howes for bringing this issue to our attention.
