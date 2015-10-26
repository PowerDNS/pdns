% IXPLORE(1)
% Pieter Lexis (pieter.lexis@powerdns.com)
% October 2015

# NAME
**ixplore** - A tool that provides insights into IXFRs

# SYNOPSIS
**ixplore** *COMMAND* *COMMAND_OPT*...

**ixplore** diff *ZONE* *BEFORE* *AFTER*

**ixplore** track *IP ADDRESS* *PORT* *ZONE* *DIRECTORY*

# DESCRIPTION
**ixplore** is a tool to work with IXFR (incremental zonetransfers)  in two modes
(specified by *COMMAND*): diff or track.

In the 'diff' mode, it will show a diff(1)-like output between *BEFORE* and *AFTER*.

In the 'track' mode, **ixplore** consumes IXFRs from *IP ADDRESS* and writes the
resulting zonefiles out to *DIRECTORY*/*ZONE*-serial. If no initial zonefiles
exist, an initial AXFR will be done first. **ixplore** will then check the SOA
serial on *IP ADDRESS* for *ZONE* every SOA Refresh seconds and perform an IXFR
if the serial has increased.

# OPTIONS
## diff-mode
ZONE
:    The name of the zone the IXFRs are consumed from.

BEFORE
:    Path to the 'before' zonefile.

AFYER
:    Path to the 'after' zonefile.


## track-mode
IP ADDRESS
:    The IP address to consume IXFRs from.

PORT
:    The port to use on *IP ADDRESS*.

ZONE
:    Name of the zone to track changes of.

DIRECTORY
:    Directory where the zonefiles will be stored.

# SEE ALSO
diff(1)
