PowerDNS Security Advisory 2008-03: Some PowerDNS Configurations can be forced to restart remotely
--------------------------------------------------------------------------------------------------

-  CVE: Not yet assigned
-  Date: 18th of November 2008
-  Affects: PowerDNS Authoritative Server 2.9.21.1 and earlier
-  Not affected: No versions of the PowerDNS Recursor
   (``pdns_recursor``) are affected. Versions not running in single
   threaded mode (``distributor-threads=1``) are probably not affected.
-  Severity: Moderate
-  Impact: Denial of Service
-  Exploit: Send PowerDNS an CH HINFO query.
-  Solution: Upgrade to PowerDNS Authoritative Server 2.9.21.2, or wait
   for 2.9.22.
-  Workaround: Remove ``distributor-threads=1`` if this is set.

Daniel Drown discovered that his PowerDNS 2.9.21.1 installation crashed
on receiving a HINFO CH query. In his enthusiasm, he shared his
discovery with the world, forcing a rapid over the weekend release
cycle.

While we thank Daniel for his discovery, please study our security
policy as outlined in `"Security" <#security>`__ before making
vulnerabilities public.

It is believed that this issue only impacts PowerDNS Authoritative
Servers operating with ``distributor-threads=1``, but even on other
configurations a database reconnect occurs on receiving a CH HINFO
query.
