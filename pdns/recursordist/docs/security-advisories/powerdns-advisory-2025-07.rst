PowerDNS Security Advisory 2025-07: Internal logic flaw in cache management can lead to a denial of service in Recursor
=======================================================================================================================

- CVE: CVE-2025-59029
- Date: 8th December 2025
- Affects: PowerDNS Recursor 5.3.0 and 5.3.1
- Not affected: PowerDNS Recursor 5.1.x, 5.2.x and 5.3.2
- Severity: Medium
- Impact: Denial of Service
- Exploit: This problem can be triggered by specific cache contents and a query with qtype ANY
- Risk of system compromise: None
- Solution: Upgrade to patched version or prevent requests with qtype ANY

CVSS Score: 5.6, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L&version=3.1

The remedy is: upgrade to a patched version or prevent requests with qtype ANY.

Version 5.3.2 of PowerDNS Recursor was never released publicly, upgrade to version 5.3.3 or newer.

