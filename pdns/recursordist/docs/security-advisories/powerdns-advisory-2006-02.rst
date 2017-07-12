PowerDNS Security Advisory 2006-02: Zero second CNAME TTLs can make PowerDNS exhaust allocated stack space, and crash
---------------------------------------------------------------------------------------------------------------------

-  CVE: CVE-2006-4252
-  Date: 13th of November 2006
-  Affects: PowerDNS Recursor versions 3.1.3 and earlier, on all
   operating systems.
-  Not affected: No versions of the PowerDNS Authoritative Server
   ('pdns\_server') are affected.
-  Severity: Moderate
-  Impact: Denial of service
-  Exploit: This problem can be triggered by sending queries for
   specifically configured domains
-  Solution: Upgrade to PowerDNS Recursor 3.1.4, or apply `commit
   919 <http://wiki.powerdns.com/projects/trac/changeset/919>`__.
-  Workaround: None known. Exposure can be limited by configuring the
   **allow-from** setting so only trusted users can query your
   nameserver.

PowerDNS would recurse endlessly on encountering a CNAME loop consisting
entirely of zero second CNAME records, eventually exceeding resources
and crashing.
