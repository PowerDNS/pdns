PowerDNS Security Advisory 2024-03: Transfer requests received over DoH can lead to a denial of service in DNSdist
==================================================================================================================

- CVE: CVE-2024-25581
- Date: May 13th 2024
- Affects: PowerDNS DNSdist 1.9.0, 1.9.1, 1.9.2 and 1.9.3, earlier versions are not affected
- Not affected: PowerDNS DNSdist 1.9.4
- Severity: High (only in specific configurations, see below)
- Impact: Denial of service
- Exploit: This problem can be triggered by a remote, unauthenticated attacker sending a DNS query
- Risk of system compromise: None
- Solution: Upgrade to patched version or apply the workaround described below

When incoming DNS over HTTPS support is enabled using the nghttp2 provider, and queries are routed to a tcp-only or
DNS over TLS backend, an attacker can trigger an assertion failure in DNSdist by sending a request for a zone transfer
(AXFR or IXFR) over DNS over HTTPS, causing the process to stop and thus leading to a Denial of Service.
DNS over HTTPS is not enabled by default, and backends are using plain DNS (Do53) by default.

`CVSS Score: 7.5 <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1>`__, only for configurations where incoming DoH is enabled and a TCP-only/DoT backend is enabled.

Two workarounds are available:

- refuse incoming XFR requests via a DNSdist rule: ``addAction(OrRule({QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}), RCodeAction(DNSRCode.REFUSED))``
- switch to the legacy h2o provider by setting ``library='h2o'`` in the ``addDOHLocal`` directive

For those unable to upgrade to a new version, a minimal patch is `available for 1.9.3 <https://downloads.powerdns.com/patches/2024-03>`__

We would like to thank Daniel Stirnimann from Switch for finding and subsequently reporting this issue.
