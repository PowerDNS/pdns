PowerDNS Security Advisory 2024-02: if recursive forwarding is configured, crafted responses can lead to a denial of service in Recursor
========================================================================================================================================

- CVE: CVE-2024-25583
- Date: 24th of April 2024.
- Affects: PowerDNS Recursor 4.8.7, 4.9.4 and 5.0.3; earlier versions are not affected
- Not affected: PowerDNS Recursor 4.8.8, 4.9.5 and 5.0.4
- Severity: High (only when using recursive forwarding)
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker publishing a crafted zone
- Risk of system compromise: None
- Solution: Upgrade to patched version

A crafted response from an upstream server the recursor has been configured to forward-recurse to can cause a Denial of
Service in the Recursor. The default configuration of the Recursor does not use recursive forwarding
and is not affected.

CVSS Score: 7.5, only for configurations using recursive forwarding, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1

The remedy is to update to a patched version.
