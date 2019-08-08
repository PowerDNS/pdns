PowerDNS Security Advisory 2019-01: Lua hooks are not applied in certain configurations
=======================================================================================

-  CVE: CVE-2019-3806
-  Date: 21st of January 2019
-  Affects: PowerDNS Recursor from 4.1.4 up to and including 4.1.8
-  Not affected: 4.0.x, 4.1.0 up to and including 4.1.3, 4.1.9
-  Severity: Low
-  Impact: Access restriction bypass
-  Exploit: This problem can be triggered via TCP queries
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: Switch to pdns-distributes-queries=no

An issue has been found in PowerDNS Recursor where Lua hooks are not properly
applied to queries received over TCP in some specific combination of settings,
possibly bypassing security policies enforced using Lua.

When the recursor is configured to run with more than one thread (threads=X)
and to do the distribution of incoming queries to the worker threads itself
(pdns-distributes-queries=yes), the Lua script is not properly loaded in
the thread handling incoming TCP queries, causing the Lua hooks to not be
properly applied.

This issue has been assigned CVE-2019-3806 by Red Hat.

PowerDNS Recursor from 4.1.4 up to and including 4.1.8 is affected.
