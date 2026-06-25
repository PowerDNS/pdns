PowerDNS Security Advisory 2026-08 for PowerDNS Recursor: Multiple Issues
=========================================================================

CVE-2026-3361: ZoneToCache can poison the cache
-----------------------------------------------

- CVE: CVE-2026-33612
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-04T00:00:00+01:00
- Affects: PowerDNS Recursor from 5.2.0 up to and including 5.4.2
- Not affected: PowerDNS Recursor 5.2.11, 5.3.8, 5.4.3
- Severity: High
- Impact: Cache poisoning, but only via the ZoneToCache function
- Exploit: When ZoneToCache is used, this problem can be triggered by an attacker sending a crafted zone.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disable ZoneToCache
- CWE: CWE-349
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:L
- Last affected: 5.2.10,5.3.7,5.4.2
- First fixed: 5.2.11,5.3.8,5.4.3
- Internal ID: 461

A malicious authoritative server can send a crafted zone via the ZoneToCache function that leads to cache poisoning.

`CVSS Score: 7.5 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:L&version=3.1>`__

The remedy is: upgrade to a patched version, or disable ZoneToCache.

We would like to thank Danial Mahadzir for bringing this issue to our attention.

CVE-2026-40012: Information about ECS zero scoped answers might leak to clients that use a specific ECS
-------------------------------------------------------------------------------------------------------

- CVE: CVE-2026-40012
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-08T00:00:00+01:00
- Affects: PowerDNS Recursor from 5.2.0 up to and including 5.4.2
- Not affected: PowerDNS Recursor 5.2.11, 5.3.8, 5.4.3
- Severity: Medium
- Impact: Information about ECS zero scoped answers might be leaked to clients that use a specific ECS.
- Exploit: If ECS is enabled clients might get results for scope zero answers from the packet cache while they should not.
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-668
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
- Last affected: 5.2.10,5.3.7,5.4.2
- First fixed: 5.2.11,5.3.8,5.4.3
- Internal ID: 464

ECS zero scoped answers are stored in the packet cache while they should not. This impacts only configurations that have ECS enabled.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N&version=3.1>`__

The remedy is: upgrade to a patched version.

CVE-2026-42005: Unbounded resource consumption in internal webserver
--------------------------------------------------------------------

- CVE: CVE-2026-42005
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-25T00:00:00+01:00
- Affects: PowerDNS Recursor from 5.2.0 up to and including 5.2.10
- Not affected: PowerDNS Recursor 5.2.11
- Severity: Medium
- Impact: Denial of service
- Exploit: his problem can be triggered by a client sending crafted HTTP queries
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L
- Last affected: 5.2.10
- First fixed: 5.2.11
- Internal ID: 481 

An attacker can send a web request that causes unlimited memory allocation in the internal web
server, leading to a denial of service. The internal web server is disabled by default.

`CVSS Score: 4.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank ilya rozentsvaig for bringing this issue to our attention.

CVE-2026-42390: ZONEMD validation can be bypassed
-------------------------------------------------

- CVE: CVE-2026-42390
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-26T00:00:00+01:00
- Affects: PowerDNS Recursor from 5.2.0 up to and including 5.4.2
- Not affected: PowerDNS Recursor 5.2.11, 5.3.8, 5.4.3
- Severity: Medium
- Impact: A zone for ZoneToCache including ZONEMD passes validation while it should not
- Exploit: A crafted zone can be made that passes ZONEMD validation while it should not
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-345
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L
- Last affected: 5.2.10,5.3.7,5.4.2
- First fixed: 5.2.11,5.3.8,5.4.3
- Internal ID: 484

An invalid zone might pass ZONEMD validation while it should not. This is only relevant if ZoneToCache is configured with ZONEMD validation.

`CVSS Score: 6.5 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank Vitaly Simonovich for bringing this issue to our attention.

CVE-2026-42390: Reject more queries with invalid header values
--------------------------------------------------------------

- CVE: CVE-2026-42390
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-20T00:00:00+01:00
- Affects: PowerDNS Recursor from 5.4.0 up to and including 5.4.2
- Not affected: PowerDNS Recursor 5.4.3
- Severity: Medium
- Impact: Cache poisoning
- Exploit: Crafted replies from authoritative servers combined with massive spoofing can lead to cache poisening
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-20
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
- Last affected: 5.4.2
- First fixed: 5.4.3
- Internal ID: 485

This fix provides extra hardening for the 5.4.x branch by doing extra validation of incoming answers from authoritative servers.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N&version=3.1>`__

The remedy is: upgrade to a patched version.

CVE-2026-42388: Missing input validation for catalog zones
----------------------------------------------------------

- CVE: CVE-2026-42388
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-25T00:00:00+01:00
- Affects: PowerDNS Recursor from 5.2.0 up to and including 5.4.2
- Not affected: PowerDNS Recursor 5.2.11, 5.3.8, 5.4.3
- Severity: Medium
- Impact: An invalid catalog zone can cause a crash, but only if catalog zones are configured
- Exploit: A crafted catalog zone might lead to a crash in Recursor
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-20
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 5.2.10,5.3.7,5.4.2
- First fixed: 5.2.11,5.3.8,5.4.3
- Internal ID: 488

Incomplete validation of the SOA record present in a catalog zone might lead to a crash.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank ylwango613 for bringing this issue to our attention.

CVE-2026-42387: Insufficient input validation in ZoneToCache
------------------------------------------------------------

- CVE: CVE-2026-42387
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-25T00:00:00+01:00
- Affects: PowerDNS Recursor from 5.2.0 up to and including 5.4.2
- Not affected: PowerDNS Recursor 5.2.11, 5.3.8, 5.4.3
- Severity: Medium
- Impact: An invalid RRSIG record used in ZoneToCache might cause a crash of the Recusor
- Exploit: When ZoneToCache is used, this problem can be triggered by an attacker sending a crafted zone.
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-20
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 5.2.10,5.3.7,5.4.2
- First fixed: 5.2.11,5.3.8,5.4.3
- Internal ID: 489

A malicious authoritative server can send a crafted zone via the ZoneToCache function that leads to
a crash of the Recursor due to insuffcient input validation.

`CVSS Score: 5.9 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H>`__

The remedy is: upgrade to a patched version.

We would like to thank nurmukhammyed for bringing this issue to our attention.

CVE-2026-52690: Spoofed answers can mark an authoritative non-EDNS capable
--------------------------------------------------------------------------

- CVE: CVE-2026-52690
- Date: 2026-06-25T00:00:00+01:00
- Discovery date: 2026-04-29T00:00:00+01:00
- Affects: PowerDNS Recursor from 5.2.0 up to and including 5.4.2
- Not affected: PowerDNS Recursor 5.2.11, 5.3.8, 5.4.3
- Severity: Medium
- Impact: DNSSEC validation of zones served by the targeted authoritative server fails
- Exploit: Spoofing answers to Recursor telling it specific authoritative servers are not EDNS capable
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-290
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 5.2.10,5.3.7,5.4.2
- First fixed: 5.2.11,5.3.8,5.4.3
- Internal ID: 493

Spoofing replies to Recursor might mark an IP of an authoritative server as not supporting EDNS,
causing valdiation of DNSSEC records served by that server to fail.

`CVSS Score: 5.9 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H>`__

The remedy is: upgrade to a patched version.

We would like to thank Mehtab Zafar for bringing this issue to our attention.
