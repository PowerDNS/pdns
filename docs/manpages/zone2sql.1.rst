zone2sql
========

Synopsis
--------

:program:`zone2sql` {**--named-conf=**\ *PATH*,\ **--zone-file=**\ *PATH* [**--zone-name=**\ *NAME*]} [*Options*]

Description
-----------

:program:`zone2sql` parses BIND named.conf files and zonefiles and outputs SQL
on standard out, which can then be fed to your database.

:program:`zone2sql` understands the BIND master file extension ``$GENERATE``
and will also honour ``$ORIGIN`` and ``$TTL``.

For backends supporting slave operation there is also an option to keep
slave zones as slaves, and not convert them to native operation.

:program:`zone2sql` can generate SQL for the Generic MySQL, Generic PostgreSQL,
Generic SQLite3 backend.

Options
-------

INPUT Options
-------------

--named-conf=<PATH>         Read *PATH* to get the BIND configuration
--zone=<PATH>               Parse only the zone file at *PATH* Conflicts with **--named-conf** parameter.
--zone-name=<NAME>          When parsing a single zone without $ORIGIN statement, set *ZONE* as
                            the zone name.

BACKENDS
--------

--gmysql
    Output in format suitable for the default configuration of the
    Generic MySQL backend.
--gpgsql
    Output in format suitable for the default configuration of the
    Generic PostgreSQL backend.
--gsqlite
    Output in format suitable for the default configuration of the
    Generic SQLite3 backend.

OUTPUT Options
--------------

--json-comments
    Parse JSON in zonefile comments to set the 'disabled' and 'comment'
    fields in the database. See *JSON COMMENTS* for more information.
--transactions
    If the target SQL backend supports transactions, wrap every domain
    into a transaction for integrity and possibly higher speed.

OTHER Options
-------------

--filter-duplicate-soa
    If there's more than one SOA record in the zone (possibly because it
    was AXFR'd), ignore it. If this option is not set, all SOA records
    in the zone are emitted.
--help
    List all options
--on-error-resume-next
    Ignore missing zone files during parsing. Dangerous.
--slave
    Maintain slave status of zones listed in named.conf as being slaves.
    The default behaviour is to convert all zones to native operation.
--verbose
    Be verbose during conversion.

JSON COMMENTS
-------------

The Generic SQL backends have the 'comment' and 'disabled' fields in the
'records' table. The 'comment' field contains a comment for this record
(if any) and the 'disabled' field tells PowerDNS if the record can be
served to clients.

When a zonefile contains a comment like
``; json={"comment": "Something", "disabled": true}`` and
**--json-comments** is provided, the 'comment' field will contain
"Something" and the 'disabled' field will be set to the database's
native true value.

WARNING: Using JSON comments to disable records means that the zone in
PowerDNS is different from the one served by BIND, as BIND does not
handle the disabled status in the comment.

See also
--------

pdns_server(1)
