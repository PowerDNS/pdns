pdns_control
============

Synopsis
--------

:program:`pdns_control` [*OPTION*]... *COMMAND*

Description
-----------

:program:`pdns_control` is used to send commands to a running PowerDNS
nameserver.

Options
-------

--help                       Show summary of options.
--chroot=<DIR>               Directory where PowerDNS is chrooted.
--config-dir=<DIR>           Location of configuration directory (pdns.conf).
--config-name=<NAME>         Name of this virtual configuration - will rename the binary image.
--remote-address=<ADDRESS>   Remote address to query.
--remote-port=<PORT>         Remote port to query.
--secret=<SECRET>            Secret needed to connect to remote PowerDNS.
--socket-dir=<DIR>           Where the controlsocket lives.

Commands
--------

bind-add-zone *ZONE* *FILENAME*
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using the BIND backend, add a zone. This zone is added in-memory
and served immediately. Note that this does not add the zone to the
bind-config file. *FILENAME* must be an absolute path.

bind-domain-extended-status [*ZONE*...]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Output an extended status of all zones, containing much more information than
the simple zone status, like the number of records currently loaded, whether pdns
is primary or secondary for the zone, the list of primaries, various timers, etc.
Optionally, append *ZONE*\ s to get the status of specific zones.

bind-domain-status [*ZONE*...]
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using the BIND backend, list status of all zones. Optionally,
append *ZONE*\ s to get the status of specific zones.

bind-list-rejects
^^^^^^^^^^^^^^^^^

When using the BIND backend, get a list of all rejected zones.

bind-reload-now *ZONE* [*ZONE*...]
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using the BIND backend, immediately reload *ZONE* from disk.

ccounts
^^^^^^^

Show the content of the cache.

current-config [diff]
^^^^^^^^^^^^^^^^^^^^^

Show the currently running configuration. The output has the same format as ``pdns_server --config``. With the diff option, only modified options are included in the output.

cycle
^^^^^

Restart the nameserver so it reloads its configuration. Only works
when the server is running in guardian mode.

list
^^^^

Dump all statistics and their values in a comma separated list,
equivalent to ``show *``.

list-zones [primary,secondary,native]
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Show a list of zones, optionally filter on the type of zones to
show.

notify *ZONE*
^^^^^^^^^^^^^^^

Adds *ZONE* to the notification list, causing PowerDNS to send out
notifications to the nameservers of a zone. Can be used if a secondary
missed previous notifications or is generally hard of hearing. Use
\* to notify for all zones. (Note that you may need to escape the
\* sign in your shell.)

notify-host *ZONE* *ADDRESS*
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Same as above but with operator specified IP *ADDRESS* as
destination, to be used if you know better than PowerDNS.

ping, rping
^^^^^^^^^^^

Check if the server is still alive. Will return 'PONG' when it is.
``ping`` works when running inside a guardian, whereas ``rping``
works when running without a guardian.

purge [*RECORD*]
^^^^^^^^^^^^^^^^

Purge entries from the cache. If *RECORD* ends with a dollar ($) all
entries that end with that name are removed. If no record is
specified the entire cache is purged.

qtypes
^^^^^^

Get a count of queries per qtype on standard output.

quit or stop
^^^^^^^^^^^^

Tell a running pdns\_server to quit.

rediscover
^^^^^^^^^^

Instructs backends that new zones may have appeared in the
database, or, in the case of the BIND backend, in named.conf.

reload
^^^^^^

Instruct the server to reload all its zones, this will not add new
zones.

remotes
^^^^^^^

Get the top number of remote addresses (clients).

respsizes
^^^^^^^^^

Get a histogram of the response sizes.

retrieve *ZONE* [IP]
^^^^^^^^^^^^^^^^^^^^^^

Retrieve secondary *ZONE* from its primary. Done nearly immediately.
If IP is specified, then retrieval is forced from the specified IP.
Port may be specified in AFI specific manner.

set *VARIABLE* *VALUE*
^^^^^^^^^^^^^^^^^^^^^^

Set the configuration parameter *VARIABLE* to *VALUE*. Currently
only the query-logging can be set.

show *STATISTIC*
^^^^^^^^^^^^^^^^

Show a single statistic, as present in the output of the list
command.

show *STATISTIC-PREFIX*\*
^^^^^^^^^^^^^^^^^^^^^^^^^

Show all statistics which names start with the supplied *STATISTIC-PREFIX*,
as a comma-separated list. Only one (ending) wildcard is allowed.

status
^^^^^^

Show usage statistics. This only works if the server is running in
guardian mode.

token-login *MODULE* *SLOT* *PIN*
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Log on to a PKCS#11 slot. You only need to login once per slot, even
if you have multiple keys on single slot. Only available if PowerDNS
was compiled with PKCS#11 support.

uptime
^^^^^^

Show the uptime of the running server.

version
^^^^^^^

Print the version of the running pdns daemon.

See also
--------

pdns\_server (1), pdnsutil (1)
