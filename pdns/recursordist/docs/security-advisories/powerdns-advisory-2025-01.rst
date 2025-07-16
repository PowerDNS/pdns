PowerDNS Security Advisory 2025-01: A crafted zone can lead to an illegal memory access in the Recursor
=======================================================================================================

- CVE: CVE-2025-30195
- Date: 7th of April 2025.
- Affects: PowerDNS Recursor 5.2.0
- Not affected: PowerDNS Recursor 5.2.1 and versions before 5.2.0
- Severity: High
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker publishing a crafted zone
- Risk of system compromise: None
- Solution: Upgrade to patched version


An attacker can publish a zone containing specific Resource Record Sets. Processing and caching results for these sets can lead to an illegal memory accesses and crash of the Recursor, causing a denial of service.

CVSS Score: 7.5, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1

The remedy is: upgrade to the patched 5.2.1 version.

We would like to thank Volodymyr Ilyin for bringing this issue to our attention.
