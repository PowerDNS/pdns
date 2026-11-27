PowerDNS Security Advisory 2026-15 for DNSdist: Multiple issues
===============================================================

CVE-2026-85561: Wrong remote DoH client IP passed to proxy-protocol-enabled backend
-----------------------------------------------------------------------------------

- CVE: CVE-2026-85561
- Date: 2026-11-12T12:00:00+01:00
- Discovery date: 2026-09-23T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.1.3 and 2.0.11
- Not affected: PowerDNS DNSdist 2.1.4, 2.0.12
- Severity: Low
- Impact: Client IP spoofing
- Exploit: This problem can be triggered by a client sending crafted DoH queries when incoming X-Forwarded-For headers are trusted and the proxy protocol is enabled toward a backend
- Risk of system compromise: None
- Solution: Upgrade to patched version, do not rely on incoming DNS over HTTPS X-Forwarded-For headers, or do not enable the proxy protocol between dnsdist and its backends
- CWE: CWE-284
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N
- Last affected: 2.1.3,2.0.11
- First fixed: 2.1.4,2.0.12
- Internal ID: 557
- External ID: YWH-PGM6095-413
- External Reporter: Vitaly Simonovich

When DNS over HTTPS is enabled and configured to trust incoming X-Forwarded-For headers, in addition to the use of the proxy protocol being enabled between DNSdist and one of its backends, an outgoing TCP connection could be wrongly reused for a query received over the same incoming DNS over HTTPS connection but with a different X-Forwarded-For header, causing the backend to consider the query as coming from the same remote client than the first query received on the outgoing connection.

`CVSS Score: 5.4 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N&version=3.1>`__

The remedy is: upgrade to a patched version, do not rely on incoming DNS over HTTPS X-Forwarded-For header, or do not enable the proxy protocol between dnsdist and its backends.

We would like to thank Vitaly Simonovich for bringing this issue to our attention.

CVE-2026-85562: Duplicate X-Forwarded-For DNS over HTTPS headers are not properly handled
-----------------------------------------------------------------------------------------

- CVE: CVE-2026-85562
- Date: 2026-11-12T12:00:00+01:00
- Discovery date: 2026-09-21T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.1.3 and 2.0.11
- Not affected: PowerDNS DNSdist 2.1.4, 2.0.12
- Severity: Medium
- Impact: Client IP spoofing
- Exploit: This problem can be triggered by a client sending crafted DoH queries when incoming X-Forwarded-For headers are trusted
- Risk of system compromise: None
- Solution: Upgrade to patched version, or do not rely on incoming DNS over HTTPS X-Forwarded-For headers
- CWE: CWE-287
- CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
- Last affected: 2.1.3,2.0.11
- First fixed: 2.1.4,2.0.12
- Internal ID: 559
- External ID: YWH-PGM6095-341
- External Reporter: Ap4sh and ethicxz

When DNS over HTTPS is enabled and configured to trust incoming X-Forwarded-For headers, and the reverse proxy placed in front of DNSdist does not replace existing X-Forwarded-For headers but merely append a new header to the query, the first header was used by DNSdist instead of the last one, making it possible for a client to spoof its own IP address.

`CVSS Score: 5.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N&version=3.1>`__

The remedy is: upgrade to a patched version, do not rely on incoming DNS over HTTPS X-Forwarded-For header, or configure the reverse proxy places in front of DNSdist to remove any existing X-Forwarded-For header.

We would like to thank Ap4sh and ethicxz for bringing this issue to our attention.

CVE-2026-85563: HTTP body should not be processed on DNS over HTTPS GET queries
-------------------------------------------------------------------------------

- CVE: CVE-2026-85563
- Date: 2026-11-12T12:00:00+01:00
- Discovery date: 2026-09-21T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.1.3 and 2.0.11
- Not affected: PowerDNS DNSdist 2.1.4, 2.0.12
- Severity: Low
- Impact: Cache pollution
- Exploit: This problem can be triggered by a client sending crafted DoH queries when a caching HTTP reverse proxy is present in front of DNSdist
- Risk of system compromise: None
- Solution: Upgrade to patched version, or do not place a caching HTTP reverse proxy in front of DNSdist
- CWE: CWE-436
- CVSS: 3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L
- Last affected: 2.1.3,2.0.11
- First fixed: 2.1.4,2.0.12
- Internal ID: 560
- External ID: YWH-PGM6095-310
- External Reporter: r0g

When DNS over HTTPS is enabled and a caching HTTP reverse proxy is used in front of DNSdist, it is possible to pollute the cache of the HTTP reverse proxy by sending DNS over HTTPS GET queries with a body. DNSdist should either refuse the query or ignore the HTTP body, but instead was processing the content of the HTTP body rather than the query present in the HTTP path.

`CVSS Score: 4.2 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L&version=3.1>`__

The remedy is: upgrade to a patched version, do not use a caching HTTP reverse proxy in front of DNSdist.

We would like to thank r0g for bringing this issue to our attention.

CVE-2026-85564: Finished QUIC streams should not linger around
--------------------------------------------------------------

- CVE: CVE-2026-85564
- Date: 2026-11-12T12:00:00+01:00
- Discovery date: 2026-09-24T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.1.3 and 2.0.11
- Not affected: PowerDNS DNSdist 2.1.4, 2.0.12
- Severity: Low
- Impact: Denial of service
- Exploit: This problem can be triggered by a client sending crafted DoQ or DoH3 queries
- Risk of system compromise: None
- Solution: Upgrade to patched version or keep DoQ and DoH3 disabled
- CWE: CWE-405
- CVSS: 3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L
- Last affected: 2.1.3,2.0.11
- First fixed: 2.1.4,2.0.12
- Internal ID: 569
- External ID: YWH-PGM6095-438
- External Reporter: Mehtab Zafar

An attacker can trigger a large memory use by cancelling QUIC streams while DNSdist is retrieving the response from its backend. Instead of releasing the memory corresponding to the cancelled stream right away, DNSdist was mistakenly keeping it around until the end of the QUIC connection.

`CVSS Score: 4.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version or keep DoQ and DoH3 disabled.

We would like to thank Mehtab Zafar for bringing this issue to our attention.

CVE-2026-85565: Denial of service via oversized DoH query
---------------------------------------------------------

- CVE: CVE-2026-85565
- Date: 2026-11-12T12:00:00+01:00
- Discovery date: 2026-09-22T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.1.3 and 2.0.11
- Not affected: PowerDNS DNSdist 2.1.4, 2.0.12
- Severity: Low
- Impact: Denial of service
- Exploit: This problem can be triggered by a client sending crafted DoH queries
- Risk of system compromise: None
- Solution: Upgrade to patched version or keep DoH disabled
- CWE: CWE-444
- CVSS: 3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L
- Last affected: 2.1.3,2.0.11
- First fixed: 2.1.4,2.0.12
- Internal ID: 570
- External ID: YWH-PGM6095-390
- External Reporter: GhostInject

An attacker can trigger a synchronization issue on outgoing TCP connections between DNSdist and its backend by sending oversized DNS over HTTPS queries. This could cause the backend to refuse queries, send a server failure, or just close the TCP connection.

`CVSS Score: 3.1 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version or keep DoH disabled.

We would like to thank GhostInject for bringing this issue to our attention.

CVE-2026-85566: EDNS option or DNS record smuggling
---------------------------------------------------

- CVE: CVE-2026-85566
- Date: 2026-11-12T12:00:00+01:00
- Discovery date: 2026-09-05T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.1.3 and 2.0.11
- Not affected: PowerDNS DNSdist 2.1.4, 2.0.12
- Severity: Medium
- Impact: Source IP forgery, DNS record or EDNS options smuggling
- Exploit: This problem can be triggered by a client sending a crafted DNS query when EDNS Client Subnet toward a backend is enabled
- Risk of system compromise: None
- Solution: Upgrade to patched version or do not enable outgoing EDNS Client Subnet
- CWE: CWE-115
- CVSS: 3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N
- Last affected: 2.1.3,2.0.11
- First fixed: 2.1.4,2.0.12
- Internal ID: 571
- External ID: YWH-PGM6095-362, YWH-PGM6095-428
- External Reporter: Naseeb Dangi, ya3raj, Vitaly Simonovich

An attacker might be able to forge its own source IP, smuggle DNS records or bypass EDNS options filtering via a specially crafted DNS query when EDNS Client Subnet is enabled between DNSdist and its backend.

`CVSS Score: 4.8 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N&version=3.1>`__

The remedy is: upgrade to a patched version or do not enable EDNS Client Subnet.

We would like to thank Naseeb Dangi, ya3raj and Vitaly Simonovich for bringing this issue to our attention.

CVE-2026-123756: Insufficient input validation of internal webserver
--------------------------------------------------------------------

- CVE: CVE-2026-123756
- Date: 2026-11-12T12:00:00+01:00
- Discovery date: 2026-09-22T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.1.3 and 2.0.11
- Not affected: PowerDNS DNSdist 2.1.4, 2.0.12
- Severity: Low
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending crafted HTTP queries to the internal webserver
- Risk of system compromise: None
- Solution: Upgrade to patched version or only open the internal webserver to trusted clients
- CWE: CWE-400
- CVSS: 3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L
- Last affected: 2.1.3,2.0.11
- First fixed: 2.1.4,2.0.12
- Internal ID: 580
- External ID: YWH-PGM6095-355, YWH-PGM6095-412
- External Reporter: Sel, lazarux0x1337 and onevilx

An attacker can cause a denial of service by sending crafted HTTP queries to the internal webserver. The webserver is not enabled by default and is protected by an ACL.

`CVSS Score: 4.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version or only open the internal webserver to trusted clients.

We would like to thank Sel, lazarux0x1337 and onevilx for bringing this issue to our attention.

CVE-2026-85567: Empty API key should disable the API
----------------------------------------------------

- CVE: CVE-2026-85567
- Date: 2026-11-12T12:00:00+01:00
- Discovery date: 2026-09-22T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.1.3 and 2.0.11
- Not affected: PowerDNS DNSdist 2.1.4, 2.0.12
- Severity: Low
- Impact: Authentication bypass
- Exploit: This problem can be triggered by an attacker sending queries to the HTTP API
- Risk of system compromise: None
- Solution: Upgrade to patched version or set a proper API key
- CWE: CWE-287
- CVSS: 3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N
- Last affected: 2.1.3,2.0.11
- First fixed: 2.1.4,2.0.12
- Internal ID: 586
- External ID: YWH-PGM6095-374
- External Reporter: swaley

Setting an empty API key was not properly disabling access to the internal HTTP API, despite being documented as such. This allowed an attacker whose IP address was allowed by the webserver ACL to bypass the authentication and get read-only access to the API.

`CVSS Score: 3.1 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N&version=3.1>`__

The remedy is: upgrade to a patched version or set a proper API key

We would like to thank swaley for bringing this issue to our attention.

CVE-2026-123755: Crafted zone transfer can freeze an outgoing TCP connection
----------------------------------------------------------------------------

- CVE: CVE-2026-123755
- Date: 2026-11-12T12:00:00+01:00
- Discovery date: 2026-09-04T00:00:00+01:00
- Affects: PowerDNS DNSdist up to and including 2.1.3 and 2.0.11
- Not affected: PowerDNS DNSdist 2.1.4, 2.0.12
- Severity: Low
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker sending XFR queries
- Risk of system compromise: None
- Solution: Upgrade to patched version or block XFR transfers from untrusted clients
- CWE: CWE-400
- CVSS: 3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L
- Last affected: 2.1.3,2.0.11
- First fixed: 2.1.4,2.0.12
- Internal ID: 590
- External ID: YWH-PGM6095-345
- External Reporter: Rajat Raghav, kylekkkk

An attacker allowed to send AXFR or IXFR queries can cause an outgoing TCP connection to the backend to be stuck, causing a denial of service to other clients trying to reuse the same outgoing connection.

`CVSS Score: 4.3 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L&version=3.1>`__

The remedy is: upgrade to a patched version or block XFR transfers from untrusted clients.

We would like to thank Rajat Raghav and kylekkkk for bringing this issue to our attention.
