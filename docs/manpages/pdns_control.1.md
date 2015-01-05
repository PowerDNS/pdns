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
:    Show the content of the cache

cycle
:    Restart the nameserver so it reloads its configuration. Only works when the
     server is running in guardian mode.

notify *DOMAIN*
:    Adds *DOMAIN* to the notification list, causing PDNS to send out
     notifications to the nameservers of a domain. Can be used if a slave missed
     previous notifications or is generally hard of hearing.

notify-host *DOMAIN* *HOST*
:    Same as above but with operator specified IP address as destination, to be
     used if you know better than PowerDNS.

ping
:    Check if the server is alive.

purge [*RECORD*]
:    Purge entries from the packet cache. If *RECORD* ends with a dollar ($)
     all entries that end with that name are removed. If no record is specified
     the entire cache is purged.

quit
:    Tell a running pdns_server to quit.

rediscover
:    Instructs backends that new domains may have appeared in the database, or,
     in the case of the Bind backend, in named.conf.

retrieve *DOMAIN*
:    Retrieve slave *DOMAIN* from its master. Done nearly immediately.

set *VARIABLE* *VALUE*
:    Set the configuration parameter *VARIABLE* to *VALUE*. Currently only the
     query-logging can be set.

show *VARIABLE*
:    Show a single statistic, as present in the output of the list command.

status
:    Show usage statistics.

uptime
:    Show the uptime of the running server.

version
:    Print the version of the running pdns daemon.

# SEE ALSO
pdns_server(1)
