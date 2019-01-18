sdig
====

Synopsis
--------

:program:`sdig` *IPADDRESS* *PORT* *QNAME* *QTYPE* [*OPTION*]

Description
-----------

:program:`sdig` sends a DNS query to *IPADDRESS* on port *PORT* and displays
the answer in a formatted way.

Options
-------

These options can be added to the commandline in any order. dnssec : Set
the DO bit to request DNSSEC information.

hidesoadetails
    Don't show the SOA serial in the response.
recurse
    Set the RD bit in the question.
showflags
    Show the NSEC3 flags in the response.
tcp
    Use TCP instead of UDP to send the query.
ednssubnet *SUBNET*
    Send *SUBNET* in the edns-client-subnet option. If this option is
    not set, no edns-client-subnet option is set in the query.
