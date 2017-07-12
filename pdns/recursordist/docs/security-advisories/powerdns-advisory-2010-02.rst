PowerDNS Security Advisory 2010-02: PowerDNS Recursor up to and including 3.1.7.1 can be spoofed into accepting bogus data
--------------------------------------------------------------------------------------------------------------------------

-  CVE: CVE-2009-4010
-  Date: 6th of January 2010
-  Affects: PowerDNS Recursor 3.1.7.1 and earlier
-  Not affected: No versions of the PowerDNS Authoritative
   ('pdns\_server') are affected.
-  Severity: High
-  Impact: Using smart techniques, it is possible to fool the PowerDNS
   Recursor into accepting unauthorized data
-  Exploit: Withheld
-  Solution: Upgrade to PowerDNS Recursor 3.1.7.2 or higher
-  Workaround: None.

Using specially crafted zones, it is possible to fool the PowerDNS
Recursor into accepting bogus data. This data might be harmful to your
users. An attacker would be able to divert data from, say, bigbank.com
to an IP address of his choosing.

This vulnerability was discovered by a third party that (for now)
prefers not to be named. PowerDNS is very grateful however for their
help in improving PowerDNS security.
