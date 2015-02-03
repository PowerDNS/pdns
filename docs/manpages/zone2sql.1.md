% ZONE2SQL(1)
% PowerDNS
% December 2002

# NAME
**zone2sql** - convert BIND zones to SQL

# SYNOPSIS
**zone2sql** {**--named-conf=***PATH*,**--zone-file=***PATH* **--zone-name=***NAME*} [*OPTIONS*]

# DESCRIPTION
**zone2sql** parses Bind named.conf files and zonefiles and outputs SQL
on standard out, which can then be fed to your database.

**zone2sql** understands the Bind master file extension `$GENERATE` and will
also honour `$ORIGIN` and `$TTL`.

For backends supporting slave operation there is also an option to keep slave
zones as slaves, and not convert them to native operation.

**zone2sql** can generate SQL for the Generic MySQL, Generic PostgreSQL and
Oracle backends.

# OPTIONS
## INPUT OPTIONS
--named-conf=*PATH*
:    Read *PATH* to get the bind configuration

--zone=*PATH*
:    Parse only the zone file at *PATH* Conflicts with **--named-conf** parameter.

--zone-name=*NAME*
:    When parsing a single zone without $ORIGIN statement, set *ZONE* as the zone
     name.

## OUTPUT OPTIONS
--gmysql
:    Output in format suitable for the default configuration of the Generic MySQL
     backend.

--gpgsql
:    Output in format suitable for the default configuration of the Generic
     PostgreSQL backend.

--oracle
:    Output in format suitable for the default configuration of the Generic Oracle
     backend.

--transactions
:    For Oracle and PostgreSQL output, wrap each domain in a transaction for higher
     speed and integrity.

## OTHER OPTIONS
--slave
:    Maintain slave status of zones listed in named.conf as being slaves. The
     default behaviour is to convert all zones to native operation.

--on-error-resume-next
:    Ignore missing files during parsing. Dangerous.

--help
:    List all options

--verbose
:    Be verbose during conversion.

# SEE ALSO
pdns_server(1)
