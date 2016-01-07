% ZONE2JSON(1)
% PowerDNS
% January 2016

# NAME
**zone2json** - convert BIND zones to JSON

# SYNOPSIS
**zone2json** {**--named-conf=***PATH*,**--zone-file=***PATH* [**--zone-name=***NAME*]} [*OPTIONS*]

# DESCRIPTION
**zone2json** parses Bind named.conf files and zonefiles and outputs JSON
on standard out, which can then be fed to the PowerDNS API.

**zone2json** understands the Bind master file extension `$GENERATE` and will
also honour `$ORIGIN` and `$TTL`.

# OPTIONS
## INPUT OPTIONS
--named-conf=*PATH*
:    Read *PATH* to get the bind configuration

--zone=*PATH*
:    Parse only the zone file at *PATH* Conflicts with **--named-conf** parameter.

--zone-name=*NAME*
:    When parsing a single zone without $ORIGIN statement, set *ZONE* as the zone
     name.

## OTHER OPTIONS
--help
:    List all options

--on-error-resume-next
:    Ignore missing zone files during parsing. Dangerous.

--verbose
:    Be verbose during conversion.

# SEE ALSO
pdns_server(1)
