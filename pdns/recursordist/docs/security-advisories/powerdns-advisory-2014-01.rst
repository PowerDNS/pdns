 PowerDNS Security Advisory 2014-01: PowerDNS Recursor 3.6.0 can be crashed remotely
------------------------------------------------------------------------------------

-  CVE: CVE-2014-3614
-  Date: 10th of September 2014
-  Credit: Dedicated PowerDNS users willing to study a crash that
   happens once every few months (thanks)
-  Affects: Only PowerDNS Recursor version 3.6.0.
-  Not affected: No other versions of PowerDNS Recursor, no versions of
   PowerDNS Authoritative Server
-  Severity: High
-  Impact: Crash
-  Exploit: The sequence of packets required is known
-  Risk of system compromise: No
-  Solution: Upgrade to PowerDNS Recursor 3.6.1
-  Workaround: Restrict service using
   |allow-from|_, install
   script that restarts PowerDNS

.. |allow-from| replace:: ``allow-from``
.. _allow-from: :ref:`setting-allow-from`

Recently, we've discovered that PowerDNS Recursor 3.6.0 (but NOT
earlier) can crash when exposed to a specific sequence of malformed
packets. This sequence happened spontaneously with one of our largest
deployments, and the packets did not appear to have a malicious origin.

Yet, this crash can be triggered remotely, leading to a denial of
service attack. There appears to be no way to use this crash for system
compromise or stack overflow.

Upgrading to 3.6.1 solves the issue.

In addition, you can apply a `minimal fix <https://xs.powerdns.com/tmp/minipatch-3.6.1>`__
to your own tree.

As for workarounds, only clients in allow-from are able to trigger the
crash, so this should be limited to your userbase. Secondly,
`this <https://github.com/PowerDNS/pdns/blob/master/contrib/upstart-recursor.conf>`__
and
`this <https://github.com/PowerDNS/pdns/blob/master/contrib/systemd-pdns-recursor.service>`__
can be used to enable Upstart and Systemd to restart the PowerDNS
Recursor automatically.
