% NSEC3DIG(1)
% PowerDNS.com BV
% April 2015

# NAME
**nsec3dig** - Show and validate NSEC3 proofs

# SYNOPSIS
**nsec3dig** *IPADDRESS* *PORT* *QNAME* *QTYPE* [recurse]

# DESCRIPTION
**nsec3dig** sends a query for *QNAME* and *QTYPE* to the nameserver at *IPADDRESS*
on port *PORT* and prints whether and why the NSEC3 proofs are correct. Using the
'recurse' option sets the Recursion Desired (RD) bit in the query.

# EXAMPLE
`nsec3dig 8.8.8.8 53 doesntexist.isoc.nl TXT recurse`
