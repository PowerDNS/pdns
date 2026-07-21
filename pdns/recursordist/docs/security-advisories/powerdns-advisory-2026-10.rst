PowerDNS Security Advisory 2026-10 for PowerDNS Recursor: Multiple Issues
=========================================================================

CVE-2026-52688: RRSIGs with too few labels can lead to bypass of DNSSEC wildcard validation
-------------------------------------------------------------------------------------------

- CVE: CVE-2026-52688
- Date: 2026-07-22T00:00:00+01:00
- Discovery date: 2026-04-12T00:00:00+01:00
- Affects: PowerDNS Recursor from up to and including 5.2.11, 5.3.8 and 5.4.3
- Not affected: PowerDNS Recursor 5.2.12, 5.3.9, 5.4.4
- Severity: High
- Impact: DNSSEC Validation bypass
- Exploit: A crafted reply can bypass DNSSEC validation of wildcards
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-345
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
- Last affected: 5.2.11,5.3.8,5.4.3
- First fixed: 5.2.12,5.3.9,5.4.4
- Internal ID: 515
- External Reporter: Qifan Zhang from Palo Alto Networks

A malicious authoritative server can send a crafted reply that leads to DNSSEC wildcard validation bypass.

`CVSS Score: 7.5 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank Qifan Zhang from Palo Alto Networks for bringing this issue to our attention.


CVE-2026-62686: Wildcard CNAME proof validation bypass
------------------------------------------------------

- CVE: CVE-2026-52686
- Date: 2026-07-22T00:00:00+01:00
- Discovery date: 2026-04-12T00:00:00+01:00
- Affects: PowerDNS Recursor from up to and including 5.2.11, 5.3.8 and 5.4.3
- Not affected: PowerDNS Recursor 5.2.12, 5.3.9, 5.4.4
- Severity: Low
- Impact: Potential cache poisoning
- Exploit: A crafted reply from an authoritative server containing specific wildcards
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-345
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N
- Last affected: 5.2.11,5.3.8,5.4.3
- First fixed: 5.2.12,5.3.9,5.4.4
- Internal ID: 518

The NSEC record related to a wildcard proof involving a CNAME is not validated, allowing cache poisoning, but only in very specific cases outside of control of an attacker.

`CVSS Score: 3.7 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank Qifan Zhang from Palo Alto Networks for bringing this issue to our attention.

