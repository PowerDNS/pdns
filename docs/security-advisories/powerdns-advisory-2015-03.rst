PowerDNS Security Advisory 2015-03: Packet parsing bug can lead to crashes
--------------------------------------------------------------------------

-  CVE: CVE-2015-5311
-  Date: November 9th 2015
-  Credit: Chris Hofstaedtler of Deduktiva GmbH
-  Affects: PowerDNS Authoritative Server 3.4.4 through 3.4.6
-  Not affected: PowerDNS Authoritative Server 3.3.x and 3.4.7 and up
-  Severity: High
-  Impact: Degraded service or Denial of service
-  Exploit: This problem can be triggered by sending specially crafted
   query packets
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: run the process inside the guardian or inside a
   supervisor

A bug was found using ``afl-fuzz`` in our packet parsing code. This bug,
when exploited, causes an assertion error and consequent termination of
the the ``pdns_server`` process, causing a Denial of Service.

When the PowerDNS Authoritative Server is run inside the guardian
(``--guardian``), or inside a supervisor like supervisord or systemd, it
will be automatically restarted, limiting the impact to a somewhat
degraded service.

PowerDNS Authoritative Server 3.4.4 - 3.4.6 are affected. No other
versions are affected. The PowerDNS Recursor is not affected.

`PowerDNS Authoritative Server
3.4.7 <../changelog.md#powerdns-authoritative-server-347>`__ contains a
fix to this issue. A minimal patch is `available
here <https://downloads.powerdns.com/patches/2015-03/>`__.

This issue is unrelated to the issues in our previous two Security
Announcements (`2015-01 <powerdns-advisory-2015-01.md>`__ and
`2015-02 <powerdns-advisory-2015-02.md>`__).

We'd like to thank Chris Hofstaedtler of Deduktiva GmbH for finding
and reporting this issue.
