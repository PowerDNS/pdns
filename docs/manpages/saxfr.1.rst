saxfr
=====

Synopsis
--------

:program:`saxfr` *IPADDRESS* *PORT* *ZONE* [*Options*]

Description
-----------

:program:`saxfr` does a zone-transfer (AXFR) of *ZONE* from the nameserver at
*IPADDRESS* on port *PORT* and displays the transferred zone with NSEC3
information truncated. See below how to show this information.

Options
-------

showdetails
    Show all the data in the NSEC3 and DNSKEY RDATA.
showflags
    Show the NSEC3 flags in the RDATA.
unhash
    Unhash the NSEC3 names to the normal names.
