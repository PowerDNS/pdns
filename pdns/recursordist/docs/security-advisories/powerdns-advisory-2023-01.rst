PowerDNS Security Advisory 2023-01: unbounded recursion results in program termination
======================================================================================

- CVE: CVE-2023-22617
- Date: 20th of January 2023
- Affects: PowerDNS Recursor 4.8.0
- Not affected: PowerDNS Recursor < 4.8.0, PowerDNS Recursor 4.8.1
- Severity: High
- Impact: Denial of service
- Exploit: This problem can be triggered by a remote attacker with access to the recursor by querying names from specific mis-configured domains
- Risk of system compromise: None
- Solution: Upgrade to patched version

CVSS 3.0 score: 8.2 (High)
https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H/E:H/RL:U/RC:C

