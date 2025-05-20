PowerDNS Security Advisory 2008-02: By not responding to certain queries, domains become easier to spoof
--------------------------------------------------------------------------------------------------------

-  CVE: CVE-2008-3337
-  Date: 6th of August 2008
-  Affects: PowerDNS Authoritative Server 2.9.21 and earlier
-  Not affected: No versions of the PowerDNS Recursor ('pdns\_recursor')
   are affected.
-  Severity: Moderate
-  Impact: Data manipulation; client redirection
-  Exploit: Domains with servers that drop certain queries can be
   spoofed using simpler measures than would usually be required
-  Solution: Upgrade to PowerDNS Authoritative Server 2.9.21.1, or apply
   `commit
   8b1ed87 <https://github.com/PowerDNS/pdns/commit/8b1ed874b009aeda37843f71e6b4ec25e75485fb>`__.
-  Workaround: None known.

Brian J. Dowling of Simplicity Communications has discovered a security
implication of the previous PowerDNS behaviour to drop queries it
considers malformed. We are grateful that Brian notified us quickly
about this problem.

The implication is that while the PowerDNS Authoritative server itself
does not face a security risk because of dropping these malformed
queries, other resolving nameservers run a higher risk of accepting
spoofed answers for domains being hosted by PowerDNS Authoritative
Servers before 2.9.21.1.

While the dropping of queries does not aid sophisticated spoofing
attempts, it does facilitate simpler attacks.
