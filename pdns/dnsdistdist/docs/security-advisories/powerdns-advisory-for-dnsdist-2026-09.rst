PowerDNS Security Advisory 2026-09 for DNSdist: Multiple issues
===============================================================

CVE-2026-40011: Prometheus denial of service via crafted DNS queries
--------------------------------------------------------------------

- CVE: CVE-2026-40011
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-07T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.0.6 and 1.9.14
- Not affected: PowerDNS DNSdist 1.9.15, 2.0.7
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by a client sending crafted queries
- Risk of system compromise: None
- Solution: Upgrade to patched version or don't use dynBlockRulesGroup():setSuffixMatchRule() or dynBlockRulesGroup():setSuffixMatchRuleFFI()
- CWE: CWE-116
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N
- Last affected: 1.9.14,2.0.6
- First fixed: 1.9.15,2.0.7
- Internal ID: 462

An attacker sending a large number of crafted DNS queries might be able to trigger a dynamic block being inserted with a value causing invalid output to be produced in the prometheus endpoint. The prometheus endpoint will then be rejected by the scraper until the dynamic block expires.

`CVSS Score: 3.7 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N&version=3.1>`__

The remedy is: upgrade to a patched version or don't use dynBlockRulesGroup():setSuffixMatchRule() or dynBlockRulesGroup():setSuffixMatchRuleFFI().

We would like to thank Haruki Oyama (Waseda University) for bringing this issue to our attention.

CVE-2026-42004: EDNS options smuggling
--------------------------------------

- CVE: CVE-2026-42004
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-24T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.0.6 and 1.9.14
- Not affected: PowerDNS DNSdist 1.9.15, 2.0.7
- Severity: Low
- Impact: Bypass of security rules
- Exploit: This problem can be triggered by a client sending crafted DNS queries
- Risk of system compromise: None
- Solution: Upgrade to patched version, do not rely on EDNS option filtering or do not enable EDNS Client Subnet insertion
- CWE: CWE-115
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N
- Last affected: 1.9.14,2.0.6
- First fixed: 1.9.15,2.0.7
- Internal ID: 490

An attacker can send a crafted EDNS OPT record that will be ignored by DNSdist's filtering rules, but will be rewritten as a valid OPT record when EDNS Client Subnet is inserted, causing the backend to see the EDNS option(s) that DNSdist did not filter.

`CVSS Score: 3.7 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N&version=3.1>`__

The remedy is: upgrade to a patched version, do not rely on EDNS option filtering or do not enable EDNS Client Subnet insertion.

We would like to thank Vitaly Simonovich for bringing this issue to our attention.

CVE-2026-42005: Insufficient input validation of internal web server
--------------------------------------------------------------------

- CVE: CVE-2026-42005
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-25T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.0.6 and 1.9.14
- Not affected: PowerDNS DNSdist 1.9.15, 2.0.7
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by a client sending crafted HTTP queries
- Risk of system compromise: None
- Solution: Upgrade to patched version or do not enable the internal webserver
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L
- Last affected: 1.9.14,2.0.6
- First fixed: 1.9.15,2.0.7
- Internal ID: 481

An attacker can send a web request that causes unlimited memory allocation in the internal web server, leading to a denial of service. The internal web server is disabled by default.

`CVSS Score: 4.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version, or prevent network access to the internal webserver. In general for defense in-depth reasons we recommend making the internal web server only accessible to trusted clients.

We would like to thank ilya rozentsvaig for bringing this issue to our attention.

CVE-2026-40208: Denial of service via DoH3 queries
--------------------------------------------------

- CVE: CVE-2026-40208
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-13T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.0.6 and 1.9.14
- Not affected: PowerDNS DNSdist 1.9.15, 2.0.7
- Severity: Low
- Impact: Denial of service
- Exploit: This problem can be triggered by a client sending crafted DoH3 queries
- Risk of system compromise: None
- Solution: Upgrade to patched version or do not enable DoH3
- CWE: CWE-705
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 1.9.14,2.0.6
- First fixed: 1.9.15,2.0.7
- Internal ID: 472

An attacker might be able to delay the processing of DoH3 queries by sending DoH3 GET queries with an invalid DATA frame.

`CVSS Score: 3.7 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version or disable DNS over HTTP/3

We would like to thank ylwango613 for bringing this issue to our attention.

CVE-2026-40209: Denial of service via IXFR queries
--------------------------------------------------

- CVE: CVE-2026-40209
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-13T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.0.6 and 1.9.14
- Not affected: PowerDNS DNSdist 1.9.15, 2.0.7
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by a client sending crafted IXFR queries
- Risk of system compromise: None
- Solution: Upgrade to patched version or block incoming IXFR queries
- CWE: CWE-772
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 1.9.14,2.0.6
- First fixed: 1.9.15,2.0.7
- Internal ID: 471

An attacker might be able to cause outgoing TCP connections to backend to be stuck until a timeout occurs instead of being released immediately. This could be used to cause a denial of service if there is a limit to the number of concurrent connections to this backend, or if the process runs out of file descriptors.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version or block incoming IXFR queries with: addAction(QTypeRule(DNSQType.IXFR), RCodeAction(DNSRCode.REFUSED))

We would like to thank Qifan Zhang (Palo Alto Networks) for bringing this issue to our attention.

CVE-2026-40210: Out-of-bounds read in SetMacAddrAction
------------------------------------------------------

- CVE: CVE-2026-40210
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-13T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.0.6 and 1.9.14
- Not affected: PowerDNS DNSdist 1.9.15, 2.0.7
- Severity: Low
- Impact: Denial of service or Information disclosure
- Exploit: This problem can be triggered by a client sending DNS queries when SetMacAddrAction is used
- Risk of system compromise: None
- Solution: Upgrade to patched version or do not use SetMacAddrAction
- CWE: CWE-126
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L
- Last affected: 1.9.14,2.0.6
- First fixed: 1.9.15,2.0.7
- Internal ID: 469

An out-of-bounds read might happen when SetMacAddrAction is used, potentially resulting in uninitialized memory being sent over the network or a crash.

`CVSS Score: 4.8 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version or do not use SetMacAddrAction

We would like to thank Qifan Zhang (Palo Alto Networks) for bringing this issue to our attention.

CVE-2026-40211: Denial of service via crafted DoH3 queries
----------------------------------------------------------

- CVE: CVE-2026-40211
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-09T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.0.6 and 1.9.14
- Not affected: PowerDNS DNSdist 1.9.15, 2.0.7
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by a client sending crafted DoH3 queries
- Risk of system compromise: None
- Solution: Upgrade to patched version or do not enable DoH3
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 1.9.14,2.0.6
- First fixed: 1.9.15,2.0.7
- Internal ID: 465

An attacker can send crafted DNS over HTTP/3 queries, triggering an exception that prevents some buffer from being freed right away. The buffer will be freed at the end of the QUIC connection, but on some setups it might be possible to open enough concurrent DoH3 streams to trigger an out-of-memory condition, resulting in a denial of service.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version or do not enable DNS over HTTP/3

We would like to thank Mehtab Zafar for bringing this issue to our attention.
