PowerDNS Security Advisory 2026-11 for PowerDNS Authoritative Server, Recursor and dnsdist: A crafted DNS packet can cause increased memory and CPU consumption
===============================================================================================================================================================

- CVE: CVE-2026-52682
- Date: 2026-08-06T00:00:00+01:00
- Discovery date: 2026-07-28T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 4.9.16, 5.0.6, 5.1.3, Recursor 5.2.12, 5.3.9, 5.4.4, and dnsdist 1.9.15, 2.0.7, 2.1.0
- Not affected: PowerDNS Authoritative Server 4.9.17, 5.0.7, 5.1.4, Recursor 5.2.13, 5.3.10, 5.4.5, and dnsdist 1.9.16, 2.0.8, 2.1.1
- Severity: High
- Impact: Increased memory and CPU usage
- Exploit: A crafted DNS packet can cause increased memory and CPU consumption
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-400
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: auth 5.1.3, 5.0.6, 4.9.16, recursor 5.2.12, 5.3.9, 5.4.4 dnsdist 1.9.15, 2.0.7, 2.1.0
- First fixed: auth 5.1.4, 5.0.7, 4.9.17, recursor 5.2.13, 5.3.10, 5.4.5, dnsdist 1.9.16, 2.0.8, 2.1.1
- Internal ID: 17796

A malicious server can send a crafted DNS packet that leads to increased memory and CPU use.

`CVSS Score: 7.5 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1>`__

The remedy is: upgrade to a patched version.

