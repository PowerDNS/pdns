PowerDNS Security Advisory 2026-03 for PowerDNS Recursor: Multiple issues
=========================================================================

CVE-2026-33256: Unbounded memory allocation by internal web server
------------------------------------------------------------------

- CVE: CVE-2026-33256
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-02-17T00:00:00+01:00
- Affects: PowerDNS Recursor from 5.3.0 up to and including 5.4.0
- Not affected: PowerDNS Recursor 5.3.6, 5.4.1
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted http requests, but only if the internal webserver is enabled.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disallow network access to web server
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 5.3.5,5.4.0
- First fixed: 5.3.6,5.4.1
- Internal ID: 365

An attacker can send a web request that causes unlimited memory allocation in the internal web
server, leading to a denial of service. The internal web server is disabled by default.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L>`__

The remedy is: upgrade to a patched version, or prevent network access to the internal webserver. In
general for defense in-depth reasons we recommend making the internal web server only accessible to
trusted clients.

We would like to thank Ap4sh - Samy Medjahed and Ethicxz - Eliott Laurie Ap4sh / Ethicxz for
bringing this issue to our attention.

CVE-2026-33257: Insufficient input validation of internal web server
--------------------------------------------------------------------

- CVE: CVE-2026-33257
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-02-16T00:00:00+01:00
- Affects: PowerDNS Recursor up to and including 5.2.8
- Not affected: PowerDNS Recursor 5.2.9
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted http requests, but only if the internal webserver is enabled.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disallow network access to web server
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 5.2.8
- First fixed: 5.2.9
- Internal ID: 368

An attacker can send a web request that causes unlimited memory allocation in the internal web
server, leading to a denial of service. The internal web server is disabled by default.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L>`__

The remedy is: upgrade to a patched version, or prevent network access to the internal webserver. In
general for defense in-depth reasons we recommend making the internal web server only accessible to
trusted clients.

We would like to thank Vitaly Simonovich for bringing this issue to our attention.

CVE-2026-33258: Crafted zones can cause increased resource usage
----------------------------------------------------------------

- CVE: CVE-2026-33258
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-02-28T00:00:00+01:00
- Affects: PowerDNS Recursor up to and including 5.2.8, 5.3.5, 5.4.0
- Not affected: PowerDNS Recursor 5.2.9, 5.3.6, 5.4.1
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted DNS responses
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 5.2.8, 5.3.5, 5.4.0
- First fixed: 5.2.9, 5.3.6, 5.4.1
- Internal ID: 369

By publishing and querying a crafted zone an attacker can cause allocation of large entries in the
negative and aggressive NSEC(3) caches.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L>`__

The remedy is: upgrade to a patched version.

We would like to thank Haruto Kimura (Stella) for bringing this issue to our attention.

CVE-2026-33259: Concurrent modification of RPZ data can lead to denial of service
---------------------------------------------------------------------------------

- CVE: CVE-2026-33259
- Date: 2026-04-22T00:00:00+01:00
- Discovery date: 2026-02-28T00:00:00+01:00
- Affects: PowerDNS Recursor up to and including 5.2.8, 5.3.5, 5.4.0
- Not affected: PowerDNS Recursor 5.2.9, 5.3.6, 5.4.1
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by having many concurrent transfers of the same RPZ
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-416
- CVSS: 3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H
- Last affected: 5.2.8, 5.3.5, 5.4.0
- First fixed: 5.2.9, 5.3.6, 5.4.1
- Internal ID: 370

Having many concurrent transfers of the same RPZ can lead to inconsistent RPZ data, use after free
and/or a crash of the recursor. Normally concurrent transfers of the same RPZ zone can only occur
with a malfunctioning RPZ provider.

`CVSS Score: 5.0 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H>`__

The remedy is: upgrade to a patched version.

We would like to thank Haruto Kimura (Stella) for bringing this issue to our attention.

CVE-2026-33260: Insufficient input validation of internal web server
--------------------------------------------------------------------

- CVE: CVE-2026-33260
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-02-20T00:00:00+01:00
- Affects: PowerDNS Recursor up to and including 5.2.8
- Not affected: PowerDNS Recursor 5.2.9
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted http requests, but only if the internal webserver is enabled.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disallow network access to web server
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 5.2.8
- First fixed: 5.2.9
- Internal ID: 374

An attacker can send a web request that causes unlimited memory allocation in the internal web
server, leading to a denial of service. The internal web server is disabled by default.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L>`__

The remedy is: upgrade to a patched version, or prevent network access to the internal webserver. In
general for defense in-depth reasons we recommend making the internal web server only accessible to
trusted clients.

We would like to thank Cavid for bringing this issue to our attention.

CVE-2026-33261: Null pointer access in aggressive NSEC(3) cache
---------------------------------------------------------------

- CVE: CVE-2026-33261
- Date: 2026-04-22T00:00:00+01:00
- Discovery date: 2026-03-13T00:00:00+01:00
- Affects: PowerDNS Recursor up to and including 5.2.8, 5.3.5, 5.4.0
- Not affected: PowerDNS Recursor 5.2.9, 5.3.6, 5.4.1
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by a zone transitioning from NSEC to NSEC3
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-353
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 5.2.8, 5.3.5, 5.4.0
- First fixed: 5.2.9, 5.3.6, 5.4.1
- Internal ID: 382

A zone transition from NSEC to NSEC3 might trigger an internal inconsistency and cause a denial of
service.

`CVSS Score: 5.9 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H>`__

The remedy is: upgrade to a patched version.

We would like to thank ylwango613 for bringing this issue to our attention.

CVE-2026-33262: Insufficient validation of cookie reply
-------------------------------------------------------

- CVE: CVE-2026-33262
- Date: 2026-04-22T00:00:00+01:00
- Discovery date: 2026-03-12T00:00:00+01:00
- Affects: PowerDNS Recursor 5.4.0
- Not affected: PowerDNS Recursor 5.4.1
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted DNS responses, but only if cookies are enabled
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-476
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 5.4.0
- First fixed: 5.4.1
- Internal ID: 386

An attacker can send replies that result in a null pointer dereference, caused by a missing
consistency check and leading to a denial of service. Cookies are disabled by default.

`CVSS Score: 5.9 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H>`__

The remedy is: upgrade to a patched version.

We would like to thank ylwango613 for bringing this issue to our attention.

CVE-2026-33601: Insufficient validation of ZONEMD record
--------------------------------------------------------

- CVE: CVE-2026-33601
- Date: 2026-04-22T00:00:00+01:00
- Discovery date: 2026-03-25T00:00:00+01:00
- Affects: PowerDNS Recursor up to and including 5.2.8, 5.3.5, 5.4.0
- Not affected: PowerDNS Recursor 5.2.9, 5.3.6, 5.4.1
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted zonemd record (only if zoneToCache is configured)
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-476
- CVSS: 3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H
- Last affected: 5.2.8, 5.3.5, 5.4.0
- First fixed: 5.2.9, 5.3.6, 5.4.1
- Internal ID: 418

If you use the zoneToCache function with a malicious authoritative server, an attacker can send a
zone that result in a null pointer dereference, caused by a missing consistency check and leading to
a denial of service.

`CVSS Score: 4.4 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank ylwango613 for bringing this issue to our attention.

CVE-2026-33600: Null pointer dereference in RPZ transfer
--------------------------------------------------------

- CVE: CVE-2026-33600
- Date: 2026-04-22T00:00:00+01:00
- Discovery date: 2026-03-27T00:00:00+01:00
- Affects: PowerDNS Recursor up to and including 5.2.8, 5.3.5, 5.4.0
- Not affected: PowerDNS Recursor 5.2.9, 5.3.6, 5.4.1
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending a crafted RPZ
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-476
- CVSS: 3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H
- Last affected: 5.2.8, 5.3.5, 5.4.0
- First fixed: 5.2.9, 5.3.6, 5.4.1
- Internal ID: 432

An RPZ sent by a malicious authoritative server can result in a null pointer dereference, caused by
a missing consistency check and leading to a denial of service.

`CVSS Score: 4.4 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H&version=3.1>`__

The remedy is: upgrade to a patched version.

We would like to thank ylwango613 for bringing this issue to our attention.
