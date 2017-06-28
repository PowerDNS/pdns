PowerDNS Security Advisory 2010-01: PowerDNS Recursor up to and including 3.1.7.1 can be brought down and probably exploited
----------------------------------------------------------------------------------------------------------------------------

-  CVE: CVE-2009-4009
-  Date: 6th of January 2010
-  Affects: PowerDNS Recursor 3.1.7.1 and earlier
-  Not affected: No versions of the PowerDNS Authoritative
   ('pdns\_server') are affected.
-  Severity: Critical
-  Impact: Denial of Service, possible full system compromise
-  Exploit: Withheld
-  Solution: Upgrade to PowerDNS Recursor 3.1.7.2 or higher
-  Workaround: None. The risk of exploitation or denial of service can
   be decreased slightly by using the ``allow-from`` setting to only
   provide service to known users. The risk of a full system compromise
   can be reduced by running with a suitable reduced privilege user and
   group settings, and possibly chroot environment.

Using specially crafted packets, it is possible to force a buffer
overflow in the PowerDNS Recursor, leading to a crash.

This vulnerability was discovered by a third party that (for now)
prefers not to be named. PowerDNS is very grateful however for their
help in improving PowerDNS security.
