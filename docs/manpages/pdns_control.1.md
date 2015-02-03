% PDNS_CONTROL(1)
% PowerDNS.com BV
% December 2002

# NAME
**pdns_control** - Contreol the PowerDNS nameserver

# SYNOPSIS
**pdns_control** [*OPTION*]... *COMMAND*

# DESCRIPTION
**pdns_control** is used to send commands to a running PowerDNS nameserver.

# OPTIONS
--help
:    Show summary of options.

--chroot=*DIR*
:    Directory where PowerDNS is chrooted.

--config-dir=*DIR*
:    Location of configuration directory (pdns.conf).

--config-name=*NAME*
:    Name of this virtual configuration - will rename the binary image.

--remote-address=*ADDRESS*
:    Remote address to query.

--remote-port=*PORT*
:    Remote port to query.

--secret=*SECRET*
:    Secret needed to connect to remote PowerDNS.

--socket-dir=*DIR*
:    Where the controlsocket lives.


# COMMANDS
ccounts
:    Show the content of the cache.

current-config
:    Show the currently running configuration.

cycle
:    Restart the nameserver so it reloads its configuration. Only works when the
     server is running in guardian mode.

list
:    Dump all variables and their values in a comma separated list, equivalent
     to **show \***.

list-zones [master,slave,native]
:    Show a list of zones, optionally filter on the type of zones to show.

notify *DOMAIN*
:    Adds *DOMAIN* to the notification list, causing PDNS to send out
     notifications to the nameservers of a domain. Can be used if a slave missed
     previous notifications or is generally hard of hearing.

notify-host *DOMAIN* *HOST*
:    Same as above but with operator specified IP address as destination, to be
     used if you know better than PowerDNS.

ping, rping
:    Check if the server is still alive. Will return 'PONG' when it is.
     **ping** works when running inside a guardian, whereas **rping** works when
     running without a guardian.

purge [*RECORD*]
:    Purge entries from the packet cache. If *RECORD* ends with a dollar ($)
     all entries that end with that name are removed. If no record is specified
     the entire cache is purged.

qtypes
:    Get a count of queries per qtype.

quit
:    Tell a running pdns_server to quit.

rediscover
:    Instructs backends that new domains may have appeared in the database, or,
     in the case of the Bind backend, in named.conf.

reload
:    Instruct the server to reload all its zones.

remotes
:    Get the top number of remote addresses.

respsizes
:    Get a histogram of the response sizes.

retrieve *DOMAIN*
:    Retrieve slave *DOMAIN* from its master. Done nearly immediately.

set *VARIABLE* *VALUE*
:    Set the configuration parameter *VARIABLE* to *VALUE*. Currently only the
     query-logging can be set.

show *VARIABLE*
:    Show a single statistic, as present in the output of the list command.

status
:    Show usage statistics. This only works if the server is running in guardian
     mode.

uptime
:    Show the uptime of the running server.

version
:    Print the version of the running pdns daemon.

# SEE ALSO
pdns_server(1)
