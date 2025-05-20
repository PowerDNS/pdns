PowerDNS Security Advisory 2014-02: PowerDNS Recursor 3.6.1 and earlier can be made to provide bad service
----------------------------------------------------------------------------------------------------------

-  CVE: CVE-2014-8601
-  Date: 8th of December 2014
-  Credit: Florian Maury (`ANSSI <https://www.ssi.gouv.fr/en/>`__)
-  Affects: PowerDNS Recursor versions 3.6.1 and earlier
-  Not affected: PowerDNS Recursor 3.6.2; no versions of PowerDNS
   Authoritative Server
-  Severity: High
-  Impact: Degraded service
-  Exploit: This problem can be triggered by sending queries for
   specifically configured domains
-  Risk of system compromise: No
-  Solution: Upgrade to PowerDNS Recursor 3.6.2
-  Workaround: None known. Exposure can be limited by configuring the
   **allow-from** setting so only trusted users can query your
   nameserver.

Recently we released PowerDNS Recursor 3.6.2 with a new feature that
strictly limits the amount of work we'll perform to resolve a single
query. This feature was inspired by performance degradations noted when
resolving domains hosted by 'ezdns.it', which can require thousands of
queries to resolve.

During the 3.6.2 release process, we were contacted by a government
security agency with news that they had found that all major caching
nameservers, including PowerDNS, could be negatively impacted by
specially configured, hard to resolve domain names. With their
permission, we continued the 3.6.2 release process with the fix for the
issue already in there.

We recommend that all users upgrade to 3.6.2 if at all possible.
Alternatively, you can apply a `minimal fix <https://downloads.powerdns.com/patches/2014-02/>`__
(including patches for older versions) to your own tree.

As for workarounds, only clients in allow-from are able to trigger the
degraded service, so this should be limited to your userbase.
