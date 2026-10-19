PowerDNS Security Advisory 2026-12 for PowerDNS Recursor: Multiple issues
=========================================================================

CVE-2026-73206: Crafted packet using compression pointers can lead to denial of service
---------------------------------------------------------------------------------------

- CVE: CVE-2026-73206
- Date: 2026-10-21T00:00:00+01:00
- Discovery date: 2026-07-10T00:00:00+01:00
- Affects: PowerDNS Recursor from up to and including 5.3.11, 5.4.7
- Not affected: PowerDNS Recursor 5.3.12, 5.4.8
- Severity: High
- Impact: Denial of Service
- Exploit: A crafted DNS packet can cause a denial of service decompressing the DNS names in the packet
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-770
- CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 5.3.11,5.4.7
- First fixed: 5.3.12,5.4.8
- Internal ID: 537
- External Reporter: Yuheng Zhang et al.

A malicious server can send a crafted reply that leads to high resource utilization decompression
name pointers in DNS packets. This is a multi-vendor issue. Multiple DNS vendors are releasing fixed
version of their products.

`CVSS Score: 7.5 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H>`__

The remedy is: upgrade to a patched version. The patched version imposes limits on the number of
decompression done for a single name and for a DNS packet as a whole.

We would like to thank Yuheng Zhang, Tsinghua University & Jingxian Technology Co., Ltd.;
Zihan Zhang, Shanghai Jiao Tong University & Jingxian Technology Co., Ltd.;
Jianjun Chen, Tsinghua University; Zihan Wang, Z.AI Co., Ltd.; and Kaiwen Shen,
CloudItera for reporting this issue and coordinating release with other vendors.

CVE-2026-73205: A malicious client can cause too many TCP connections in TIME_WAIT state
----------------------------------------------------------------------------------------

- CVE: CVE-2026-73205
- Date: 2026-10-21T00:00:00+01:00
- Discovery date: 2026-08-27T00:00:00+01:00
- Affects: PowerDNS Recursor from up to and including 5.3.11, 5.4.7
- Not affected: PowerDNS Recursor 5.3.12, 5.4.8
- Severity: Medium
- Impact: No further outgoing TCP connections can be created
- Exploit: A malicious client can cause too many TCP connections in TIME_WAIT state
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-664
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 5.3.11,5.4.7
- First fixed: 5.3.12,5.4.8
- Internal ID: 538
- External Reporter: Jonathan Horovitz, Yehuda Afek, Anat Bremler-Barr

A closed outgoing TCP connection still takes up OS resources for a short amount of time. Having a
lot of these closed connections active can prevent new connections to authoritative servers from
being opened.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N%2FAC:L%2FPR:N%2FUI:N%2FS:U%2FC:N%2FI:N%2FA:L>`__

The remedy is: upgrade to a patched version. On Linux, the impact of this issue can be reduced by
lowering the tcp_max_tw_buckets kernel variable to less than 64k. Note that default value depends on
the available memory in the system.

We would like to thank Jonathan Horovitz, Yehuda Afek and Anat Bremler-Barr for reporting this issue.

CVE-2026-85555: DNSSEC validation bypass and cache poisoning in PowerDNS Recursor via out-of-band NS resolution
----------------------------------------------------------------------------------------------------------------

- CVE: CVE-2026-85555
- Date: 2026-10-21T00:00:00+01:00
- Discovery date: 2026-09-21T00:00:00+01:00
- Affects: PowerDNS Recursor from up to and including 5.3.11, 5.4.7
- Not affected: PowerDNS Recursor 5.3.12, 5.4.8
- Severity: High
- Impact: DNSSEC validation bypass in specific cases
- Exploit: DNSSEC validation bypass and cache poisoning in PowerDNS Recursor via out-of-band NS resolution
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-345
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
- Last affected: 5.3.11,5.4.7
- First fixed: 5.3.12,5.4.8
- Internal ID: 553
- External Reporter: cookiejack15

If an NS records refers to an out-of-band (local) zone, DNSSEC validation could be skipped for the
remainder of the processing of the query, while the validation should only be skipped for the
resolving of the NS name itself.

`CVSS Score: 7.5 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N%2FAC:L%2FPR:N%2FUI:N%2FS:U%2FC:N%2FI:H%2FA:N&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank cookiejack15 for reporting this issue.

CVE-2026-85556: Missing OPT RR owner-name validation bypasses ECS hardening
---------------------------------------------------------------------------

- CVE: CVE-2026-85556
- Date: 2026-10-21T00:00:00+01:00
- Discovery date: 2026-09-21T00:00:00+01:00
- Affects: PowerDNS Recursor from up to and including 5.3.11, 5.4.7
- Not affected: PowerDNS Recursor 5.3.12, 5.4.8
- Severity: High
- Impact: An EDNS option that should be rejected is accepted
- Exploit: Missing OPT RR owner-name validation bypasses ECS hardening
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-20
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N
- Last affected: 5.3.11,5.4.7
- First fixed: 5.3.12,5.4.8
- Internal ID: 554
- External Reporter: Aarush Gaur

EDNS records should be owned by the root. The existing code did not check that in all cases.

`CVSS Score: 5.9 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N%2FAC:H%2FPR:N%2FUI:N%2FS:U%2FC:H%2FI:N%2FA:N&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank Aarush Gaur for reporting this issue.

CVE-2026-85557: Single web client not doing TLS handshake monopolizes web access
--------------------------------------------------------------------------------

- CVE: CVE-2026-85557
- Date: 2026-10-21T00:00:00+01:00
- Discovery date: 2026-09-21T00:00:00+01:00
- Affects: PowerDNS Recursor from up to and including 5.3.11, 5.4.7
- Not affected: PowerDNS Recursor 5.3.12, 5.4.8
- Severity: Medium
- Impact: Denial of service on web access port
- Exploit: Single web client not doing TLS handshake monopolizes web access
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-833
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 5.3.11,5.4.7
- First fixed: 5.3.12,5.4.8
- Internal ID: 555
- External Reporter: Vitaly Simonovich

If incoming TLS is configured for the internal web server, a single client can monopolize web
access. Note that TLS is not enabled by default for the internal web server.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N%2FAC:L%2FPR:N%2FUI:N%2FS:U%2FC:N%2FI:N%2FA:L&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank Vitaly Simonovich for reporting this issue.

CVE-2026-85558: Recursor retains closed TCP client addresses until process exit
-------------------------------------------------------------------------------

- CVE: CVE-2026-85558
- Date: 2026-10-21T00:00:00+01:00
- Discovery date:  2026-09-21T00:00:00+01:00
- Affects: PowerDNS Recursor from up to and including 5.3.11, 5.4.7
- Not affected: PowerDNS Recursor 5.3.12, 5.4.8
- Severity: Low
- Impact: Unlimited resource consumption
- Exploit: Recursor retains closed TCP client addresses until process exit
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L
- Last affected: 5.3.11,5.4.7
- First fixed: 5.3.12,5.4.8
- Internal ID: 564
- External Reporter: mzfr

A small memory leaks exist because client addresses of incoming TCP connections are stored but
never cleaned up.

`CVSS Score: 3.7 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N%2FAC:H%2FPR:N%2FUI:N%2FS:U%2FC:N%2FI:N%2FA:L&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank mzfr for reporting this issue.

CVE-2026-85559: Out-of-bounds read in Recursor findScopeZero
------------------------------------------------------------

- CVE: CVE-2026-85559
- Date: 2026-10-21T00:00:00+01:00
- Discovery date: 2026-10-23T00:00:00+01:00
- Affects: PowerDNS Recursor from up to and including 5.3.11, 5.4.7
- Not affected: PowerDNS Recursor 5.3.12, 5.4.8
- Severity: Medium
- Impact: Potential crash of Recursor
- Exploit: Out-of-bounds read in Recursor findScopeZero due to incorrect length
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-125
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 5.3.11,5.4.7
- First fixed: 5.3.12,5.4.8
- Internal ID: 566
- External Reporter: Abdulrahman Essam

The bound of the scope zero check is used incorrectly, resulting in a potential out-of-bounds
read. This only applies to configuration where incoming.use_incoming_edns_subnet is enabled.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N%2FAC:L%2FPR:N%2FUI:N%2FS:U%2FC:N%2FI:N%2FA:L&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank Abdulrahman Essam for reporting this issue.

