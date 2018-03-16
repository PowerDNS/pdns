ixfrdist
========

Synopsis
--------

:program:`ixfrdist` [*OPTION*]... *DOMAIN* [*DOMAIN*]...

Description
-----------

:program:`ixfrdist` transfers zones from an authoritative server and re-serves these zones over AXFR and IXFR.
It checks the SOA serial for all *DOMAIN*\ s from the server set with **--server-address** and downloads new versions to **--work-dir**.
This working directory has the following structure: ``work-dir/ZONE/SERIAL``, e.g. ``work-dir/rpz.example./2018011902``.

When a SOA query comes in on the address(es) set with **--listen-address**, :program:`ixfrdist` responds with the latest SOA for the zone it has.
This query can be followed up with an IXFR or AXFR query, which will then be served.
Should an IXFR be served, :program:`ixfrdist` will condense the diff into the IXFR.

When using **--uid** or **--gid** the **--work-dir** directory will be accessed (and potentially created) as the proved user/group.

Options
-------

--help       Show all supported options
--verbose    Log INFO messages
--debug      Log INFO and DEBUG messages
--version    Display the version of ixfrdist
--listen-address <ADDRESS>      Listen on *ADDRESS* for incoming queries.
                                *ADDRESS* may contain a port number, when unset 53 is assumed.
                                This option can be given multiple times.
                                When not set, 127.0.0.1:53 is assumed.
--server-address <ADDRESS>      IP address and port of the upstream server.
                                127.0.0.1:5300 by default.
--work-dir <DIR>                Path to a directory where the AXFR data are saved.
                                By default, this is the current working directory.
--keep <NUM>                    Keep at most *NUM* versions of any zone.
                                By default, 20 versions are kept.
--uid <UID>                     Drop effective user-id to *UID* after binding the listen sockets
--gid <GID>                     Drop effective group-id to *GID* after binding the listen sockets

See also
--------

ixplore(1), pdns_server(1)
