PowerDNS Security Advisory 2025-04: A Recursor configured to send out ECS enabled queries can be sensitive to spoofing attempts
===============================================================================================================================

- CVE: CVE-2025-30192
- Date: 21st July 2025
- Affects: PowerDNS Recursor up to and including 5.0.10, 5.1.4 and 5.2.2, but only if outgoing ECS is enabled
- Not affected: PowerDNS Recursor 5.0.12, 5.1.6 and 5.2.4 (5.0.11, 5.1.5 and 5.2.3 were not released publicly)
- Severity: High (only if outgoing ECS is enabled)
- Impact: Cache pollution
- Exploit: This problem can be triggered by an attacker sending spoofed replies to an ECS enabled Recursor
- Risk of system compromise: None
- Solution: Upgrade to patched version, disable outgoing ECS (the default is disabled)

An attacker spoofing answers to ECS enabled requests sent out by the Recursor has a chance
of success higher than non-ECS enabled queries.
The updated version include various mitigations against spoofing attempts of ECS enabled
queries by chaining ECS enabled requests and enforcing stricter validation of the received
answers.
The most strict mitigation done when the new setting outgoing.edns_subnet_harden (old
style name edns-subnet-harden) is enabled.

CVSS Score: 7.5, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1

The remedy is: upgrade to a patched version or disable outgoing ECS enabled queries, which is the default.

We would like to thank Xiang Li of AOSP Lab Nankai University for bringing this issue to our attention.
