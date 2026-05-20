PowerDNS Security Advisory 2026-06: Multiple Issues
===================================================

Concurrency and locking defects in GSS-TSIG
-------------------------------------------

- CVE: CVE-2026-42002
- Date: 2026-05-06T00:00:00+00:00
- Affects: PowerDNS Authoritative Server 4.7.0 up to and including 4.9.14 and 5.0.4
- Not affected: PowerDNS Authoritative Server 4.9.15, 5.0.5
- Severity: Medium
- Impact: Denial of service
- Exploit: Concurrent TKEY queries for the same key may accidentally share the same GSS-TSIG data structures and cause memory corruption or unexpected server exit.
- Risk of system compromise: None
- Solution: Upgrade to patched version or disable gss-tsig support in server configuration
- CWE: CWE-364
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 4.9.14,5.0.4
- First fixed: 4.9.15,5.0.5
- Internal ID: 381

Multiple concurrency and locking defects in the GSS-TSIG code can lead to
memory corruption due to accidental data structure sharing, which can in turn
lead to a program crash.

Moreover, the lack of bounds on the number of in-flight GSS-TSIG contexts can
lead to unbounded memory consumption in case of an excessive number of requests
at a given time. A limit of 1000 contexts is now enforced, and can be modified
with the "gss-max-contexts" parameter in server configuration.

Insufficient Validation of Autoprimary SOA Queries
--------------------------------------------------

- CVE: CVE-2026-42001
- Date: 2026-05-06T00:00:00+00:00
- Affects: PowerDNS Authoritative Server 4.1.0 up to and including 4.9.14 and 5.0.4
- Not affected: PowerDNS Authoritative Server 4.9.15, 5.0.5
- Severity: High
- Impact: Denial of service
- Exploit: Ill-formed answer to SOA query from server operating in autosecondary mode
- Risk of system compromise: None
- Solution: Upgrade to patched version, or disable autosecondary operation
- CWE: CWE-400
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- Last affected: 4.9.14,5.0.4
- First fixed: 4.9.15,5.0.5
- Internal ID: 467

Missing sanity checks of the answer to the initial SOA query, when running in
autosecondary mode and receiving a notification for a not-yet-known domain
may cause the server to crash.

Insufficient Validation of Names During AXFR
--------------------------------------------

- CVE: CVE-2026-42000
- Date: 2026-05-06T00:00:00+00:00
- Affects: PowerDNS Authoritative Server up to and including 4.9.14 and 5.0.4
- Not affected: PowerDNS Authoritative Server 4.9.15, 5.0.5
- Severity: Medium
- Impact: Denial of service
- Exploit: AXFR of zone with specific contents to Bind backend
- Risk of system compromise: None
- Solution: Upgrade to patched version
- CWE: CWE-77
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N
- Last affected: 4.9.14,5.0.4
- First fixed: 4.9.15,5.0.5
- Internal ID: 474

Missing escaping of special characters (such as $ or @) in DNS names received
during an AXFR operation can lead to an incorrect (non-parsable) Bind backend
configuration to be written, causing this backend to fail until manual
operation is performed to fix the configuration.

Incorrect Behaviour of Views with TCP PROXY Requests
----------------------------------------------------

- CVE: CVE-2026-41999
- Date: 2026-05-06T00:00:00+00:00
- Affects: PowerDNS Authoritative Server 5.0.0 up to and including 5.0.4
- Not affected: PowerDNS Authoritative Server 5.0.5
- Severity: Medium
- Impact: Information Disclosure
- Exploit: TCP query using PROXY Protocol
- Risk of system compromise: None
- Solution: Upgrade to patched version or disable views feature
- CWE: CWE-284
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N
- Last affected: 5.0.4
- First fixed: 5.0.5
- Internal ID: 482

When using views, queries sent using TCP Proxy Protocol will select the view
according to the address of the proxy, rather than the address of the initial
query. This can lead to wrong data being returned.

Insufficient Validation of Member Zone Data May Cause Catalog Zone Transfer to Fail
-----------------------------------------------------------------------------------

- CVE: CVE-2026-42396
- Date: 2026-05-06T00:00:00+00:00
- Affects: PowerDNS Authoritative Server 4.7.0 up to and including 4.9.14 and 5.0.4
- Not affected: PowerDNS Authoritative Server 4.9.15, 5.0.5
- Severity: Medium
- Impact: Denial of service
- Exploit: AXFR of catalog zone with a member whose producer group option
contains a double-quote character
- Risk of system compromise: None
- Solution: Upgrade to patched version, or remove all double-quote characters from producer group names.
- CWE: CWE-94
- CVSS: 3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H
- Last affected: 4.9.14,5.0.4
- First fixed: 4.9.15,5.0.5
- Internal ID: 483

Missing proper escaping of double-quote characters when computing labels will
cause AXFR of a catalog zone with a member whose producer group option contains
such a character to fail.
