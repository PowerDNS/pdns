PowerDNS Security Advisory 2024-04: Crafted responses can lead to a denial of service due to cache inefficiencies in the Recursor
=================================================================================================================================

- CVE: CVE-2024-25590
- Date: 3rd of October 2024.
- Affects: PowerDNS Recursor up to and including 4.9.8, 5.0.8 and 5.1.1
- Not affected: PowerDNS Recursor 4.9.9, 5.0.9 and 5.1.2
- Severity: High
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker publishing a crafted zone
- Risk of system compromise: None
- Solution: Upgrade to patched version

An attacker can publish a zone containing specific Resource Record Sets. Repeatedly processing and caching results for these sets can lead to a denial of service.

CVSS Score: 7.5, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1

The remedy is: upgrade to a patched version

We would like to thank Toshifumi Sakaguchi for bringing this issue to our attention and assisting in validating the patches.
