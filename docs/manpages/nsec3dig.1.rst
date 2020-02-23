nsec3dig
========

Synopsis
--------

:program:`nsec3dig` *IPADDRESS* *PORT* *QNAME* *QTYPE* [recurse]

Description
-----------

:program:`nsec3dig` sends a query for *QNAME* and *QTYPE* to the nameserver at
*IPADDRESS* on port *PORT* and prints whether and why the NSEC3 proofs
are correct. Using the 'recurse' option sets the Recursion Desired (RD)
bit in the query.

Example
-------

``nsec3dig 8.8.8.8 53 doesnotexist.isoc.nl TXT recurse``
