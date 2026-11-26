PowerDNS Security Advisory 2026-14: Multiple Issues
===================================================

Incomplete domain name sanitization during Bind autosecondary zone transfer
---------------------------------------------------------------------------

- CVE: CVE-2026-123757
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-06-22T00:00:00+01:00
- Affects: PowerDNS Authoritative Server up to and including 4.9.18, 5.0.8 and 5.1.5
- Not affected: PowerDNS Authoritative Server 4.9.19, 5.0.9 and 5.1.6
- Severity: Low
- Impact: Denial of Service
- Exploit: This problem can be triggered by an attacker sending crafted notify packets, but only if the Bind backend is used and the Authoritative server operates in autosecondary mode.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disable autosecondary mode, or limit bind-autoprimaries to trusted addresses only
- CWE: CWE-94
- CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H
- Last affected: 4.9.18,5.0.8,5.1.5
- First fixed: 4.9.19,5.0.9,5.1.6
- Internal ID: 514

An attacker can send a notify request that causes the root zone to be added as a secondary domain to be added to the bind backend, but causes said backend to update its configuration to an invalid one, leading to the backend no longer able to run on the next restart, requiring manual operation to fix it.

The general case of this problem was addressed by SA-2026-05, but the root zone was not handled correctly. This is now fixed.

`CVSS Score: 7.4 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H>`__

The remedy is: upgrade to a patched version, or disable autosecondary operation, if the Bind backend is used, or limit bind-autoprimaries to trusted addresses only.

Race condition in forward notification handling
-----------------------------------------------

- CVE: CVE-2026-123758
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-04-11T00:00:00+01:00
- Affects: PowerDNS Authoritative Server up to and including 4.9.18, 5.0.8 and 5.1.5
- Not affected: PowerDNS Authoritative Server 4.9.19, 5.0.9 and 5.1.6
- Severity: High
- Impact: Denial of Service
- Exploit: 
- Risk of system compromise: None
- Solution: Upgrade to patched version, or disable forward-notify.
- CWE: CWE-364
- CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H
- Last affected: 4.9.18,5.0.8,5.1.5
- First fixed: 4.9.19,5.0.9,5.1.6
- Internal ID: 568

A race condition in the handling of the forward notification requests queue can lead to a crash if too many UDP notify packets for a given zone are received in a short time frame.

`CVSS Score: 4.4 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H>`..

The remedy is: upgrade to a patched version, or disable forward-notify.

Insufficient input validation of internal webserver
---------------------------------------------------

- CVE: CVE-2026-123756
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-09-22T00:00:00+01:00
- Affects: PowerDNS Authoritative Server up to and including 4.9.18, 5.0.8 and 5.1.5
- Not affected: PowerDNS Authoritative Server 4.9.19, 5.0.9 and 5.1.6
- Severity: Low
- Impact: Denial of Service
- Exploit: This problem can be triggered by an attacker sending crafted HTTP queries to the internal webserver
- Risk of system compromise: None
- Solution: Upgrade to patched version or only open the internal webserver to trusted clients
- CWE: CWE-400
- CVSS: 3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L
- Last affected: 4.9.18,5.0.8,5.1.5
- First fixed: 4.9.19,5.0.9,5.1.6
- Internal ID: 580
- External ID: YWH-PGM6095-355, YWH-PGM6095-412
- External Reporter: Sel, lazarux0x1337 and onevilx

An attacker can cause a denial of service by sending crafted HTTP queries to the internal webserver. The webserver is not enabled by default and is protected by an ACL.

`CVSS Score: 4.3 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L>`__

The remedy is: upgrade to a patched version or only open the internal webserver to trusted clients.

We would like to thank Sel, lazarux0x1337 and onevilx for bringing this issue to our attention.

Catalog zones incorrectly accept the root zone as a member
----------------------------------------------------------

- CVE: CVE-2026-123759
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-09-22T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 4.7.0 up to and including 4.9.18, 5.0.8 and 5.1.5
- Not affected: PowerDNS Authoritative Server 4.9.19, 5.0.9 and 5.1.6, and versions earlier than 4.7.0
- Severity: High
- Impact: Denial of Service
- Exploit: Malicious provider can add a root zone as member and cause provisioning of the root zone from an untrusted source
- Risk of system compromise: None
- Solution: Upgrade to patched version, or do not use catalog zones
- CWE: CWE-284
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L
- Last affected: 4.9.18,5.0.8,5.1.5
- First fixed: 4.9.19,5.0.9,5.1.6
- Internal ID: 581

A catalog zone provider can add a root zone as member and cause PowerDNS to provision it from the given source.

`CVSS Score: 4.8 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L>`__

The remedy is: upgrade to a patched version, or do not use catalog zones.

Logic flaw in LMDB backend can lead to an unresponsive server
-------------------------------------------------------------

- CVE: CVE-2026-123760
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-09-22T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 5.1.0 to 5.1.5
- Not affected: PowerDNS Authoritative Server prior to 5.1.0, and 5.1.6
- Severity: High
- Impact: Denial of Service
- Exploit: When using the LMDB backend, performing zone rectification when the number of Empty Non-Terminal entries is larger than the max-ent-entries setting triggers a logic bug and causes the PowerDNS process to spin with the LMDB database locked.
- Risk of system compromise: None
- Solution: Upgrade to patched version, use a different backend than LMDB, or make sure not to have more empty non-terminals than max-ent-entries
- CWE: CWE-400
- CVSS: 3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
- Last affected: 5.1.5
- First fixed: 5.1.6
- Internal ID: 587

When using the LMDB backend, performing zone rectification when the number of Empty Non-Terminal entries is larger than the max-ent-entries setting triggers a logic bug and causes the PowerDNS process to spin with the LMDB database locked.

`CVSS Score: 6.5 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H>`__

The remedy is: upgrade to a patched version, use a different backend than LMDB, or make sure not to have more empty non-terminals than max-ent-entries.

Multiple defects in Views processing
------------------------------------

- CVE: CVE-2026-123761
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-09-22T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 5.x up to and including 5.0.8 and 5.1.5
- Not affected: PowerDNS Authoritative Server prior to 5.0, as well as 5.0.9 and 5.1.6
- Severity: High
- Impact: Denial of Service
- Exploit: Various logic errors in view processing can cause incorrect cached results to be returned
- Risk of system compromise: None
- Solution: Upgrade to patched version, disable packet cache or do not use the Views feature
- CWE: CWE-349
- CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L
- Last affected: 5.0.8,5.1.5
- First fixed: 5.0.9,5.1.6
- Internal ID: 588

Various logic errors in view processing can cause incorrect cached results to be returned.

`CVSS Score: 8.2 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L>`__

The remedy is: upgrade to a patched version, disable packet cache or do not use the Views feature.

Catalog zone update operation may misbehave in multi-backend configurations
---------------------------------------------------------------------------

- CVE: CVE-2026-123762
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-09-22T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 4.7.0 up to and including 4.9.18, 5.0.8 and 5.1.5
- Not affected: PowerDNS Authoritative Server 4.9.19, 5.0.9 and 5.1.6, and versions earlier than 4.7.0
- Severity: High
- Impact: Denial of Service
- Exploit: A catalog zone update introducing a new zone which already exists, but in a different backend than the one storing the catalog zone, will cause a duplicate zone to be created in that backend, and (depending on the backend load order) may completely hide the existing zone.
- Risk of system compromise: None
- Solution: Upgrade to patched version, or do not use catalog zones
- CWE: CWE-284
- CVSS: 3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:L
- Last affected: 4.9.18,5.0.8,5.1.5
- First fixed: 4.9.19,5.0.9,5.1.6
- Internal ID: 589

A catalog zone update introducing a new zone which already exists, but in a different backend than the one storing the catalog zone, will cause a duplicate zone to be created in that backend, and (depending on the backend load order) may completely hide the existing zone.

`CVSS Score: 7.6 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:L>`__

The remedy is: upgrade to a patched version, or do not use catalog zones.

Injection vulnerabilities in Bind backend
-----------------------------------------

- CVE: CVE-2026-123764
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-09-21T00:00:00+01:00
- Affects: PowerDNS Authoritative Server up to and including 4.9.18, 5.0.8 and 5.1.5
- Not affected: PowerDNS Authoritative Server 4.9.19, 5.0.9 and 5.1.6
- Severity: High
- Impact: Denial of Service
- Exploit: Incorrect sanitization of received data during zone AXFR to Bind backend can cause wrong or invalid data to be serialized
- Risk of system compromise: None
- Solution: Upgrade to patched version, or do not allow AXFR of zones served by the Bind backend
- CWE: CWE-93
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N
- Last affected: 4.9.18,5.0.8,5.1.5
- First fixed: 4.9.19,5.0.9,5.1.6
- Internal ID: 593, 597

Incorrect sanitization of received data during zone AXFR to Bind backend can cause wrong or invalid data to be serialized.

`CVSS Score: 7.5 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N>`__

The remedy is: upgrade to a patched version, or do not allow AXFR of zones served by the Bind backend.

AXFR of obsolete record types can corrupt zones in the Bind backend
-------------------------------------------------------------------

- CVE: CVE-2026-124727
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-09-21T00:00:00+01:00
- Affects: PowerDNS Authoritative Server up to and including 4.9.18, 5.0.8 and 5.1.5
- Not affected: PowerDNS Authoritative Server 4.9.19, 5.0.9 and 5.1.6
- Severity: Medium
- Impact: Denial of Service
- Exploit: Incorrect handling of obsolete record types during zone AXFR to Bind backend will cause the zone to fail to load afterwards
- Risk of system compromise: None
- Solution: Upgrade to patched version, or do not allow AXFR of zones served by the Bind backend
- CWE: CWE-229
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H
- Last affected: 4.9.18,5.0.8,5.1.5
- First fixed: 4.9.19,5.0.9,5.1.6
- Internal ID: 594

Incorrect handling of obsolete record types during zone AXFR to Bind backend will cause the zone to fail to load afterwards, requiring manual intervention to edit the zone file.

`CVSS Score: 6.5 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H>`__

The remedy is: upgrade to a patched version, or do not allow AXFR of zones served by the Bind backend.

TSIG operation logic flaws
--------------------------

- CVE: CVE-2026-124728
- Date: 2026-11-12T00:00:00+01:00
- Discovery date: 2026-09-21T00:00:00+01:00
- Affects: PowerDNS Authoritative Server up to and including 4.9.18, 5.0.8 and 5.1.5
- Not affected: PowerDNS Authoritative Server 4.9.19, 5.0.9 and 5.1.6
- Severity: High
- Impact: Denial of Service
- Exploit: Incomplete GSS negotiation, as well as TKEY context deletion while a pending operation will need to be signed with that key, can lead to a crash
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-400
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 4.9.18,5.0.8,5.1.5
- First fixed: 4.9.19,5.0.9,5.1.6
- Internal ID: 596

Incomplete GSS negotiation, as well as TKEY context deletion while a pending operation will need to be signed with that key, can lead to a crash.

`CVSS Score: 7.5 <https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H>`__

The remedy is: upgrade to a patched version.

