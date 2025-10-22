PowerDNS Security Advisory 2025-06: Crafted delegations or IP fragments can poison cached delegations in Recursor
=================================================================================================================

- CVE: CVE-2025-59023
- Date: 15th October 2025
- Affects: PowerDNS Recursor up to and including 5.1.7, 5.2.5 and 5.3.0
- Not affected: PowerDNS Recursor 5.1.8, 5.2.6 and 5.3.1
- Severity: High
- Impact: Cache pollution
- Exploit: This problem can be triggered by an attacker spoofing crafted delegations
- Risk of system compromise: None
- Solution: Upgrade to patched version

CVSS Score: 8.2, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L&version=3.1

- CVE: CVE-2025-59024
- Date: 15th October 2025
- Affects: PowerDNS Recursor up to and including 5.1.7, 5.2.5 and 5.3.0
- Not affected: PowerDNS Recursor 5.1.8, 5.2.6 and 5.3.1
- Severity: Medium
- Impact: Cache pollution
- Exploit: This problem can be triggered by an attacker using an UDP IP fragments attack
- Risk of system compromise: None
- Solution: Upgrade to patched version

CVSS Score: 6.5 see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L&version=3.1

It has been brought to our attention that the Recursor does not apply strict enough validation of received delegation information.
The malicious delegation information can be sent by an attacker spoofing packets.
The patched versions of the Recursor apply strict validation of the received delegation information from authoritative servers.
In versions 5.2.6 and 5.3.1 the already existing validations are tightened further, while version 5.1.8 contains a full backport of the strict validations.
Note that other vendors will release updated software to fix similar issues as well.

The remedy is: upgrade to a patched version.

We would like to thank Yuxiao Wu, Yunyi Zhang, Baojun Liu, and Haixin Duan from Tsinghua University and
Shiming Liu from Network and Information Security Lab, also Tsinghua University for bringing these issues to our attention.
