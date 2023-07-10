PowerDNS Security Advisory 2023-02: Deterred spoofing attempts can lead to authoritative servers being marked unavailable
=========================================================================================================================

- CVE: CVE-2023-26437
- Date: 29th of March 2023
- Affects: PowerDNS Recursor up to and including 4.6.5, 4.7.4 and 4.8.3
- Not affected: PowerDNS Recursor 4.6.6, 4.7.5 and 4.8.4
- Severity: Low
- Impact: Denial of service
- Exploit: Successful spoofing may lead to authoritative servers being marked unavailable
- Risk of system compromise: None
- Solution: Upgrade to patched version

When the recursor detects and deters a spoofing attempt or receives certain malformed DNS packets,
it throttles the server that was the target of the impersonation attempt so that other authoritative
servers for the same zone will be more likely to be used in the future, in case the attacker
controls the path to one server only. Unfortunately this mechanism can be used by an attacker with
the ability to send queries to the recursor, guess the correct source port of the corresponding
outgoing query and inject packets with a spoofed IP address to force the recursor to mark specific
authoritative servers as not available, leading a denial of service for the zones served by those
servers.

CVSS 3.0 score: 3.7 (Low)
https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:N/A:L

Thanks to Xiang Li from Network and Information Security Laboratory, Tsinghua University for reporting this issue.


