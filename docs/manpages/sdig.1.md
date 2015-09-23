% SDIG(1)
% PowerDNS.com BV
% September 2015

# NAME
**sdig** - Perform a DNS query and show the results

# SYNOPSIS
**sdig** *IPADDRESS* *PORT* *QNAME* *QTYPE* [*OPTIONS*]

# DESCRIPTION
**sdig** sends a DNS query to *IPADDRESS* on port *PORT* and displays the answer
in a formatted way.

# OPTIONS
These options can be added to the commandline in any order.
dnssec
:    Set the DO bit to request DNSSEC information.

hidesoadetails
:    Don't show the SOA serial in the response.

recurse
:    Set the RD bit in the question.

showflags
:    Show the NSEC3 flags in the response.

tcp
:    Use TCP instead of UDP to send the query.
