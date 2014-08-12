# PowerDNS Internals
PDNS is normally launched by the init.d script but is actually a binary called `pdns_server`. This file is started by the **start** and **monitor** commands to the init.d script. Other commands are implemented using the controlsocket.

# Controlsocket
The controlsocket is the means to contact a running PDNS daemon, or as we now know, a running `pdns_server`. Over this sockets, instructions can be sent using the `pdns_control` program. Like the `pdns_server`, this program is normally accessed via the init.d script.

# `pdns_control`
To communicate with PDNS over the controlsocket, the `pdns\_control` command is used. The init.d script also calls pdns\_control. The syntax is simple: `pdns\_control command arguments`. Currently this is most useful for telling backends to rediscover domains or to force the transmission of notifications. See [Master](../authoritative/modes-of-operation.md#master).

Besides the commands implemented by the init.d script, for which see [Running The Authoritative Server](../authoritative/installation.md), the following `pdns_control` commands are available:

## `ccounts`
Returns counts on the contents of the cache.

## `current-config`
Retrieves the current configuration settings from the PDNS instance. This can be useful to generate a from a running instance.

The output has the same format as `pdns_server --config`. You'll notice that all the are uncommented. This is because PDNS simply has values, and the default isn't known at runtime.

## `cycle`
Restart a PowerDNS instance. Only available when running in guardian mode.

## `notify DOMAIN`
Adds a domain to the notification list, causing PDNS to send out notifications to the nameservers of a domain. Can be used if a slave missed previous notifications or is generally hard of hearing.

## `notify-host DOMAIN HOST`
Same as above but with operator specified IP address as destination, to be used if you know better than PowerDNS.

## `ping`
'PING' the powerdns-guardian. Will return 'PONG' when it is available. (Only works when you are running in guardian mode)

## `purge`
Purges the entire Packet Cache - see [Authoritative Server Performance](../authoritative/performance.md).

## `purge RECORD`
Purges all entries for this exact record name - see [Authoritative Server Performance](../authoritative/performance.md).

## `purge RECORD`
Purges all cache entries ending on this name, effectively purging an entire domain - see [Authoritative Server Performance](../authoritative/performance.md).

## `purge`
Purges the entire Packet Cache - see [Authoritative Server Performance](../authoritative/performance.md).

## `rping`
'PING' the powerdns-instance. Will return 'PONG' when it is available.

## `rediscover`
Instructs backends that new domains may have appeared in the database, or, in the case of the Bind backend, in named.conf.

## `reload`
Instructs backends that the contents of domains may have changed. Many backends ignore this, the Bind backend will check timestamps for all zones (once queries come in for it) and reload if needed.

## `retrieve DOMAIN`
Retrieve a slave domain from its master. Done nearly immediately.

## `set VARIABLE VALUE`
Set a configuration parameter. Currently only the 'query-logging' parameter can be set.

## `uptime`
Reports the uptime of the daemon in human readable form.

## `show VARIABLE`
Show a specific statistic. Use \* for all. (You may need to quote as '\*' or \\\*).

## `version`
Returns the version of a running pdns daemon.

## `status`
Retrieves the status of PowerDNS. Only available when running with guardian.
