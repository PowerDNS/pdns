zone2json
=========

Synopsis
--------

:program:`zone2json` {**--named-conf=**\ *PATH*, **--zone-file=**\ *PATH* [**--zone-name=**\ *NAME*]} [*OPTION*]

Description
-----------

:program:`zone2json` parses BIND named.conf files and zonefiles and outputs
JSON on standard out, which can then be fed to the PowerDNS API.

:program:`zone2json` understands the BIND master file extension ``$GENERATE``
and will also honour ``$ORIGIN`` and ``$TTL``.

Options
-------

INPUT Options
-------------

--named-conf=<PATH>        Read *PATH* to get the BIND configuration
--zone=<PATH>              Parse only the zone file at *PATH* Conflicts with ``--named-conf`` parameter.
--zone-name=<NAME>         When parsing a single zone without $ORIGIN statement, set *ZONE* as the zone name.

OTHER Options
-------------

--help                           List all options
--on-error-resume-next           Ignore missing zone files during parsing. Dangerous.
--verbose                        Be verbose during conversion.

See also
--------

pdns_server(1)
