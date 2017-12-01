ixplore
=======

Synopsis
--------

:program:`ixplore` *COMMAND* *COMMAND_OPT*...

:program:`ixplore` diff *ZONE* *BEFORE* *AFTER*

:program:`ixplore` track *IP ADDRESS* *PORT* *ZONE* *DIRECTORY*

Description
-----------

:program:`ixplore` is a tool to work with IXFR (incremental zonetransfers) in
two modes (specified by *COMMAND*): diff or track.

In the 'diff' mode, it will show a diff(1)-like output between *BEFORE*
and *AFTER*.

In the 'track' mode, :program:`ixplore` consumes IXFRs from *IP ADDRESS* and
writes the resulting zonefiles out to *DIRECTORY*/*ZONE*-serial. If no
initial zonefiles exist, an initial AXFR will be done first. :program:`ixplore`
will then check the SOA serial on *IP ADDRESS* for *ZONE* every SOA
Refresh seconds and perform an IXFR if the serial has increased.

Options
-------

diff-mode
---------

ZONE
    The name of the zone the IXFRs are consumed from.
BEFORE
    Path to the 'before' zonefile.
AFYER
    Path to the 'after' zonefile.

track-mode
----------

IP ADDRESS
    The IP address to consume IXFRs from.
PORT
    The port to use on *IP ADDRESS*.
ZONE
    Name of the zone to track changes of.
DIRECTORY
    Directory where the zonefiles will be stored.

See also
--------

diff(1)
