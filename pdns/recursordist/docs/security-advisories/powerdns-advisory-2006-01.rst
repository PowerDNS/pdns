PowerDNS Security Advisory 2006-01: Malformed TCP queries can lead to a buffer overflow which might be exploitable
------------------------------------------------------------------------------------------------------------------

-  CVE: CVE-2006-4251
-  Date: 13th of November 2006
-  Affects: PowerDNS Recursor versions 3.1.3 and earlier, on all
   operating systems.
-  Not affected: No versions of the PowerDNS Authoritative Server
   ('pdns\_server') are affected.
-  Severity: Critical
-  Impact: Potential remote system compromise.
-  Exploit: As far as we know, no exploit is available as of 11th of
   November 2006.
-  Solution: Upgrade to PowerDNS Recursor 3.1.4, or apply the patches
   referred below and recompile
-  Workaround: Disable TCP access to the Recursor. This will have slight
   operational impact, but it is likely that this will not lead to
   meaningful degradation of service. Disabling access is best performed
   at packet level, either by configuring a firewall, or instructing the
   host operating system to drop TCP connections to port 53.
   Additionally, exposure can be limited by configuring the
   ``allow-from`` setting so only trusted users can query your
   nameserver.

PowerDNS Recursor 3.1.3 and previous miscalculate the length of incoming
TCP DNS queries, and will attempt to read up to 4 gigabytes of query
into a 65535 byte buffer.

We have not verified if this problem might actually lead to a system
compromise, but are acting on the assumption that it might.

For distributors, a minimal patch is available on `the PowerDNS
wiki <http://wiki.powerdns.com/cgi-bin/trac.fcgi/changeset/915>`__.
Additionally, those shipping very old versions of the PowerDNS Recursor
might benefit from this
`patch <https://berthub.eu/tmp/cve-2006-4251.patch>`__.

The impact of these and other security problems can be lessened by
considering the advice in FIXME: security-settings.
