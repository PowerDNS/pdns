pdns_control
============

Synopsis
--------

:program:`pdns_control` [OPTION]... <COMMAND>

Description
-----------

:program:`pdns_control` is used to send commands to a running PowerDNS
nameserver.

Options
-------

.. option:: --help

   Show summary of options.

.. option:: --chroot=<DIR>

   Directory where PowerDNS is chrooted.

.. option:: --config-dir=<DIR>

   Location of configuration directory (pdns.conf).

.. option:: --config-name=<NAME>

   Name of this virtual configuration - will rename the binary image.

.. option:: --remote-address=<ADDRESS>

   Remote address to query.

.. option:: --remote-port=<PORT>

   Remote port to query.

.. option:: --secret=<SECRET>

   Secret needed to connect to remote PowerDNS.

.. option:: --socket-dir=<DIR>

   Where the controlsocket lives.

Commands
--------

General commands
^^^^^^^^^^^^^^^^

.. option:: ping, rping

   Check if the server is still alive. Will return 'PONG' when it is.
   ``ping`` works when running inside a guardian, whereas ``rping``
   works when running without a guardian.

.. option:: version

   Print the version of the running pdns daemon.

.. option:: quit, stop

   Tell a running pdns\_server to quit.

.. option:: rediscover

   Instructs backends that new zones may have appeared in the
   database, or, in the case of the BIND backend, in named.conf.

.. option:: reload

   Instruct the server to reload all its zones, this will not add new zones.

BIND-backend commands
^^^^^^^^^^^^^^^^^^^^^

.. option:: bind-add-zone <ZONE> <FILENAME>

   When using the BIND backend, add a zone. This zone is added in-memory
   and served immediately. Note that this does not add the zone to the
   bind-config file. *FILENAME* must be an absolute path.

.. option:: bind-domain-extended-status [ZONE]...

   Output an extended status of all zones, containing much more information than
   the simple zone status, like the number of records currently loaded, whether pdns
   is primary or secondary for the zone, the list of primaries, various timers, etc.
   Optionally, append *ZONE*\ s to get the status of specific zones.

.. option:: bind-domain-status [ZONE]...

   When using the BIND backend, list status of all zones. Optionally,
   append *ZONE*\ s to get the status of specific zones.

.. option:: bind-list-rejects

   When using the BIND backend, get a list of all rejected zones.

.. option:: bind-reload-now <ZONE> [ZONE]...

   When using the BIND backend, immediately reload *ZONE* from disk.

Cache commands
^^^^^^^^^^^^^^

.. option:: ccounts

   Show the content of the cache.

.. option:: purge [RECORD]

   Purge entries from the cache. If *RECORD* ends with a dollar ($) all
   entries that end with that name are removed. If no record is
   specified the entire cache is purged.

EDNS COOKIE commands
^^^^^^^^^^^^^^^^^^^^

.. option:: cookie-secret <COMMAND> [OPTIONS]

   Manage EDNS Cookie secrets.

   COMMAND is one of ``list``, ``add``, or ``delete``.

.. option:: cookie-secret list

   List all the existing EDNS Cookie secrets.
   The active secret is marked with a ``*``.

.. option:: cookie-secret add <SECRET|random>

   Add a new Cookie secret. This will become the active secret.

   *SECRET* must be 32 hexadecimal characters, or the word "random" to have the server generate a key.

   .. note::

      This secret will not be written to the configuration file.

.. option:: cookie-secret delete <SECRET|last>

   Delete an inactive Cookie secret.

   SECRET must be 32 hexadecimal characters, matching an inactive secret.
   Alternatively, the "last" keyword can be used to remove the last secret.
   This will be the secret listed at the bottom of ``cookie-secret list``.

   .. note::

      This secret will not be removed from the configuration file.

Configuration commands
^^^^^^^^^^^^^^^^^^^^^^

.. option:: current-config [diff]

   Show the currently running configuration. The output has the same format as ``pdns_server --config``. With the diff option, only modified options are included in the output.

.. option:: cycle

   Restart the nameserver so it reloads its configuration. Only works
   when the server is running in guardian mode.


.. option:: set <VARIABLE> <VALUE>

   Set the configuration parameter *VARIABLE* to *VALUE*. Currently
   only the query-logging can be set.

Data commands
^^^^^^^^^^^^^

.. option:: flush

   Flush all backend data to stable storage.
   There is usually no such data during regular operation, unless the LMDB backend
   is used with :ref:`setting-lmdb-write-notification-update` set to ``no``.

Zone commands
^^^^^^^^^^^^^

.. option:: list-zones [primary|secondary|native]

   Show a list of zones, optionally filter on the type of zones to show.

.. option:: notify <ZONE>

   Adds *ZONE* to the notification list, causing PowerDNS to send out
   notifications to the nameservers of a zone. Can be used if a secondary
   missed previous notifications or is generally hard of hearing. Use
   \* to notify for all zones. (Note that you may need to escape the
   \* sign in your shell.)

.. option:: notify-host <ZONE> <ADDRESS>

   Same as above but with operator specified IP *ADDRESS* as
   destination, to be used if you know better than PowerDNS.

.. option:: retrieve <ZONE> [IP]

   Retrieve secondary *ZONE* from its primary. Done nearly immediately.
   If *IP* is specified, then retrieval is forced from the specified IP.
   Port may be specified in AFI specific manner.

PKCS#11 commands
^^^^^^^^^^^^^^^^

.. option:: token-login <MODULE> <SLOT> <PIN>

   Log on to a PKCS#11 slot. You only need to login once per slot, even
   if you have multiple keys on single slot. Only available if PowerDNS
   was compiled with PKCS#11 support.

Statistics commands
^^^^^^^^^^^^^^^^^^^

.. option:: list

   Dump all statistics and their values in a comma separated list,
   equivalent to ``show *``.

.. option:: show <STATISTIC>

   Show a single statistic, as present in the output of the list command.

   When *STATISTIC* ends with a \*,  all statistics which names start with that name are shown as a comma-separated list.
   Only one (ending) wildcard is allowed.

.. option:: status

   Show usage statistics. This only works if the server is running in
   guardian mode.

.. option:: remotes

   Get the top number of remote addresses (clients).

.. option:: respsizes

   Get a histogram of the response sizes.

.. option:: qtypes

   Get a count of queries per qtype on standard output.

.. option:: uptime

   Show the uptime of the running server.

See also
--------

pdns\_server (1), pdnsutil (1)
