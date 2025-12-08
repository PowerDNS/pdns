PowerDNS Security Advisory 2025-08: Insufficient validation of incoming notifies over TCP can lead to a denial of service in Recursor
=====================================================================================================================================

- CVE: CVE-2025-59030
- Date: 8th December 2025
- Affects: PowerDNS Recursor up to and including 5.3.2, 5.2.6 and 5.1.8
- Not affected: PowerDNS Recursor 5.3.3, 5.2.7 and 5.1.9
- Severity: High
- Impact: Denial of Service
- Exploit: This problem can be triggered by a notify arriving over TCP and allows clearing caches
- Risk of system compromise: None
- Solution: Upgrade to patched version or prevent incoming notifies over TCP

CVSS Score: 7.5, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1

The remedy is: upgrade to patched version or prevent incoming notifies over TCP.
