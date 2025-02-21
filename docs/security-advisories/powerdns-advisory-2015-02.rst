PowerDNS Security Advisory 2015-02: Packet parsing bug can cause thread or process abortion
-------------------------------------------------------------------------------------------

-  CVE: CVE-2015-5230
-  Date: 2nd of September 2015
-  Credit: Pyry Hakulinen and Ashish Shukla at Automattic
-  Affects: PowerDNS Authoritative Server 3.4.0 through 3.4.5
-  Not affected: PowerDNS Authoritative Server 3.4.6
-  Severity: High
-  Impact: Degraded service or Denial of service
-  Exploit: This problem can be triggered by sending specially crafted
   query packets
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: Run the Authoritative Server inside a supervisor when
   ``distributor-threads`` is set to ``1`` to prevent Denial of Service.
   No workaround for the degraded service exists

A bug was found in our DNS packet parsing/generation code, which, when
exploited, can cause individual threads (disabling service) or whole
processes (allowing a supervisor to restart them) to crash with just one
or a few query packets.

PowerDNS Authoritative Server 3.4.0-3.4.5 are affected. No other
versions are affected. The PowerDNS Recursor is not affected.

`PowerDNS Authoritative Server
3.4.6 <../changelog.rst#powerdns-authoritative-server-346>`__ contains a
fix to this issue. A minimal patch is `available
here <https://downloads.powerdns.com/patches/2015-02/>`__.

This issue is entirely unrelated to `Security Advisory
2015-01 <powerdns-advisory-2015-01.rst>`__/CVE-2015-1868.

We'd like to thank Pyry Hakulinen and Ashish Shukla at Automattic for
finding and subsequently reporting this bug.
