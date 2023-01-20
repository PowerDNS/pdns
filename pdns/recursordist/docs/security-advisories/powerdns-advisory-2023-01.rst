PowerDNS Security Advisory 2023-01: unbounded recursion results in program termination
======================================================================================

- CVE: CVE-2023-22617
- Date: 20th of January 2023
- Affects: PowerDNS Recursor 4.8.0
- Not affected: PowerDNS Recursor < 4.8.0, PowerDNS Recursor 4.8.1
- Severity: High
- Impact: Denial of service
- Exploit: This problem can be triggered by a remote attacker with access to the recursor by querying names from specific mis-configured domains
- Risk of system compromise: None
- Solution: Upgrade to patched version

An issue in the processing of queries for misconfigured domains has been found in PowerDNS Recursor
4.8.0, allowing a remote attacker to crash the recursor by sending a DNS query for one of these
domains.  The issue happens because the recursor enters a unbounded loop, exceeding its stack
memory. Because of the specific way in which this issue happens, we do not believe this issue to be
exploitable for code execution.

PowerDNS Recursor versions before 4.8.0 are not affected.

Note that when the PowerDNS Recursor is run inside a supervisor like supervisord or systemd, a crash
will lead to an automatic restart, limiting the impact to a somewhat degraded service.

CVSS 3.0 score: 8.2 (High)
https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H/E:H/RL:U/RC:C

Thanks to applied-privacy.net for reporting this issue and their assistance in diagnosing it.

