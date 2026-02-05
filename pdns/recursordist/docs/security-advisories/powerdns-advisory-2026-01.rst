PowerDNS Security Advisory 2026-01: Crafted zones can lead to increased resource usage in Recursor
==================================================================================================

- CVE: CVE-2026-24027
- Date: 9th February 2026
- Affects: PowerDNS Recursor up and including to 5.1.9, 5.2.7 and 5.3.4
- Not affected: PowerDNS Recursor 5.1.10, 5.2.8 and 5.3.5
- Severity: Medium
- Impact: Denial of Service
- Exploit: This problem can be triggered by publishing and querying a crafted zone that causes increased incoming network traffic.
- Risk of system compromise: None
- Solution: Upgrade to patched version

CVSS Score: 5.3, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L&version=3.1

The remedy is: upgrade to a patched version.

We would like to thank Shuhan Zhang from Tsinghua University for bringing this issue to our attention.

- CVE: CVE-2026-0398
- Date: 9th February 2026
- Affects: PowerDNS Recursor up and including to 5.1.9, 5.2.7 and 5.3.4
- Not affected: PowerDNS Recursor 5.1.10, 5.2.8 and 5.3.5
- Severity: Medium
- Impact: Denial of Service
- Exploit: This problem can be triggered by publishing and querying a crafted zone that causes large memory usage.
- Risk of system compromise: None
- Solution: Upgrade to patched version

CVSS Score: 5.3, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L&version=3.1

The remedy is: upgrade to a patched version.

We would like to thank Yufan You from Tsinghua University for bringing this issue to our attention.

We would also like to thank TaoFei Guo from Peking University and Yang Luo, JianJun Chen from
Tsinghua University for bringing an issue of caching irrelevant records related to CNAME chains to
our attention.
