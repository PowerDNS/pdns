PowerDNS Security Advisory 2026-05: Multiple Issues
===================================================

Insufficient input validation of internal webserver
---------------------------------------------------

- CVE: CVE-2026-33257
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-02-16T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 3.4.0 up to and including 5.0.3 and 4.9.13
- Not affected: PowerDNS Authoritative Server 4.9.14, 5.0.4
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted http requests, but only if the internal webserver is enabled.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disallow network access to web server
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 4.9.13,5.0.3
- First fixed: 4.9.14,5.0.4
- Internal ID: 368

An attacker can send a web request that causes unlimited memory allocation in
the internal web server, leading to a denial of service. The internal web server
is disabled by default.

`https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`

The remedy is: upgrade to a patched version, or prevent network access to the
internal webserver. In general, for defense in-depth reasons, we recommend
making the internal web server only accessible to trusted users.

We would like to thank Vitaly Simonovich for bringing this issue to our
attention.

Insufficient input validation of internal webserver
---------------------------------------------------

- CVE: CVE-2026-33260
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-02-20T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 3.4.0 up to and including 5.0.3 and 4.9.13
- Not affected: PowerDNS Authoritative Server 4.9.14, 5.0.4
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted http requests, but only if the internal webserver is enabled.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disallow network access to web server
- CWE: CWE-770
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Last affected: 4.9.13,5.0.3
- First fixed: 4.9.14,5.0.4
- Internal ID: 374

An attacker can send a web request that causes unlimited memory allocation in
the internal web server, leading to a denial of service. The internal web server
is disabled by default.

`https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`

The remedy is: upgrade to a patched version, or prevent network access to the
internal webserver. In general, for defense in-depth reasons, we recommend
making the internal web server only accessible to trusted clients.

We would like to thank Cavid for bringing this issue to our attention.

Insufficient validation of HTTPS and SVCB records
-------------------------------------------------

- CVE: CVE-2026-33611
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-03-08T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 4.7.0 up to and including 5.0.3 and 4.9.13
- Not affected: PowerDNS Authoritative Server 4.9.14, 5.0.4
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by a trusted user sending crafted REST API requests
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-190
- CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H
- Last affected: 4.9.13,5.0.3
- First fixed: 4.9.14,5.0.4
- Internal ID: 377

An operator allowed to use the REST API can cause the Authoritative server to
produce invalid HTTPS or SVCB record data, which can in turn cause LMDB database
corruption, if using the LMDB backend.

`https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H`

The remedy is: upgrade to a patched version.

We would like to thank Tibs for bringing this issue to our
attention.

Possible file descriptor exhaustion in forward-dnsupdate
--------------------------------------------------------

- CVE: CVE-2026-33610
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-03-12T00:00:00+01:00
- Affects: PowerDNS Authoritative Server up to and including 5.0.3 and 4.9.13
- Not affected: PowerDNS Authoritative Server 4.9.14, 5.0.4
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by a rogue primary server answering to
a forward dnsupdate performed by a secondary server.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disable forward dnsupdate operation
- CWE: CWE-400
- CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 4.9.13,5.0.3
- First fixed: 4.9.14,5.0.4
- Internal ID: 380

A rogue primary server may cause file descriptor exhaustion and eventually a
denial of service, when a PowerDNS secondary server forwards a DNS update
request to it.

`https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`

The remedy is: upgrade to a patched version, or disable forward dnsupdate
operation, or restrict allowed dnsupdate addresses to trusted primary servers.

We would like to thank ylwango613 for bringing this issue to our
attention.

LDAP DN injection
-----------------

- CVE: CVE-2026-33609
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-03-23T00:00:00+01:00
- Affects: PowerDNS Authoritative Server 4.0.0 up to and including 5.0.3 and 4.9.13
- Not affected: PowerDNS Authoritative Server 4.9.14, 5.0.4
- Severity: Medium
- Impact: Information Leak
- Exploit: This problem can be triggered by regular DNS queries, but only if the Authoritative Server runs with the LDAP backend and 8bit-dns is enabled.
- Risk of system compromise: None
- Solution: Upgrade to patched version or do not enable 8bit-dns
- CWE: CWE-90
- CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
- Last affected: 4.9.13,5.0.3
- First fixed: 4.9.14,5.0.4
- Internal ID: 408

Incomplete escaping of LDAP queries when running with 8bit-dns enabled allows
users to perform queries of internal domain subtrees.

`https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`

The remedy is: upgrade to a patched version, or do not enable 8bit-dns.

We would like to thank ylwango613 for bringing this issue to our
attention.

Incomplete domain name sanitization during Bind autosecondary zone transfer
---------------------------------------------------------------------------

- CVE: CVE-2026-33608
- Date: 2026-04-22T00:00:00+01:00
- Discovery date:  2026-03-24T00:00:00+01:00
- Affects: PowerDNS Authoritative Server up to and including 5.0.3 and 4.9.13
- Not affected: PowerDNS Authoritative Server 4.9.14, 5.0.4
- Severity: High
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted notify packets, but only if the Bind backend is used and the Authoritative server operates in autosecondary mode.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disable autosecondary mode, or limit bind-autoprimaries to trusted addresses only
- CWE: CWE-94
- CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H
- Last affected: 4.9.13,5.0.3
- First fixed: 4.9.14,5.0.4
- Internal ID: 419

An attacker can send a notify request that causes a new secondary domain to be
added to the bind backend, but causes said backend to update its configuration
to an invalid one, leading to the backend no longer able to run on the next
restart, requiring manual operation to fix it.

`https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`

The remedy is: upgrade to a patched version, or disable autosecondary operation,
if the Bind backend is used, or limit bind-autoprimaries to trusted addresses
only.

We would like to thank Vitaly Simonovich for bringing this issue to our
attention.
