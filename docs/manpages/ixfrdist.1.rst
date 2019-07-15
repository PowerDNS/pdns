ixfrdist
========

Synopsis
--------

:program:`ixfrdist` [*OPTION*]...

Description
-----------

:program:`ixfrdist` transfers zones from an authoritative server and re-serves these zones over AXFR and IXFR.
It checks the SOA serial for all configured domains and downloads new versions to disk.

When a SOA query comes in and the client's address is allowed by the ACL, :program:`ixfrdist` responds with the latest SOA for the zone it has.
This query can be followed up with an IXFR or AXFR query, which will then be served to the client.
Should an IXFR be served, :program:`ixfrdist` will condense all differences it has for the domain into one IXFR.

:program:`ixfrdist` is configured with a configuration file in YAML format.
Please see :manpage:`ixfrdist.yml(5)` for information.

Options
-------

--help            Show all supported options
--verbose         Log INFO messages
--debug           Log INFO and DEBUG messages
--version         Display the version of ixfrdist
--config <PATH>   Load configuration from *PATH*, a YAML file. When not set,
                  an `ixfrdist.yml` is attempted to be read from the SYSCONFDIR.

See also
--------

ixplore(1), pdns_server(8), ixfrdist.yml(5)
