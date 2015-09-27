% PDNS_RECURSOR(1)
% PowerDNS.COM BV
% March 2008

# NAME
**pdns_recursor** - high-performance, simple and secure recursing nameserver

# SYNOPSIS
**pdns_recursor** [*OPTION*]...

# DESCRIPTION
pdns_recursor(1) is a high performance,  simple  and  secure  recursing
nameserver.  It currently powers over two million internet connections.

The recursor is configured via a configuration file, but each  item  in
that file can be overridden on the command line.

This  manpage lists the core set of features needed to get the PowerDNS
recursor  working,  for  full  and  up  to   date   details   head   to
http://doc.powerdns.com/built-in-recursor.html

# EXAMPLES
To listen on 192.0.2.53 and allow the 192.0.2.0/24 subnet to recurse, and run
as a daemon, execute:

`# pdns_recursor --local-address=192.0.2.53 --allow-from=192.0.2.0/24 --daemon`

To stop the recursor by hand, run:

`# rec_control quit`

However, the recommended way of starting and stopping the recursor is to use
the init.d script provided.

# OPTIONS
For authoritative listing of options, consult the online documentation at
http://doc.powerdns.com/md/recursor/settings/

--allow-from=*NETWORK*[,*NETWORK*]...
:    If set, only allow these comma separated *NETWORK*s, with network mask to
     recurse. For example: 192.0.2.0/24,203.0.113.128/25.

--auth-zones=*ZONENAME*=*FILENAME*[,*ZONENAME*=*FILENAME*]...
:    Serve *ZONENAME* from *FILENAME* authoritatively. For example:
     ds9a.nl=/var/zones/ds9a.nl,powerdns.com=/var/zones/powerdns.com.

--chroot=*DIRECTORY*
:    chroot the process to *DIRECTORY*.

--client-tcp-timeout=*NUM*
:    Timeout in seconds when talking to TCP clients.

--config-dir=*DIRECTORY*
:    Location of configuration directory (recursor.conf), /etc/powerdns by
     default.

--daemon
:    Operate as a daemon.

--delegation-only
:    Which domains we only accept delegations from (a Verisign special).

--entropy-source=*FILE*
:    Read new entropy from *FILE*, defaults to /dev/urandom.

--export-etc-hosts
:    If set, this flag will export the hostnames and IP addresses mentioned in
     /etc/hosts.

--forward-zones=*ZONENAME*=*ADDRESS*[,*ZONENAME*=*ADDRESS*]...
:    Queries for *ZONENAME* will be forwarded to *ADDRESS*. *ADDRESS*
     should be an IP address, not a hostname (to prevent chicken and egg
     problems). Example:
     forward-zones= ds9a.nl=213.244.168.210, powerdns.com=127.0.0.1.

--forward-zones-file=*FILENAME*
:    Similar to *--forward-zones*, but read the options from *FILENAME*.
     *FILENAME* should contain one zone per line, like: ds9a.nl=213.244.168.210.

--help
:    Show a summary of options.

--hint-file=*FILENAME*
:    Load root hints from this *FILENAME*

--local-address=*ADDRESS*[,*ADDRESS*]...
:    Listen on *ADDRESS*, separated by spaces or commas.

--local-port=*PORT*
:    Listen on *PORT*.

--log-common-errors
:    If we should log rather common errors.

--max-cache-entries=*NUM*
:    Maximum number of entries in the main cache.

--max-negative-ttl=*NUM*
:    maximum number of seconds to keep a negative cached entry in memory.

--max-tcp-clients=*NUM*
:    Maximum number of simultaneous TCP clients.

--max-tcp-per-client
:    If set, maximum number of TCP sessions per client (IP address).

--query-local-address=*ADDRESS*
:    Use *ADDRESS* as Source IP address when sending queries.

--query-local-address6=*ADDRESS*
:    Send out local IPv6 queries from *ADDRESS*. Disabled by default,
     which also disables outgoing IPv6 support. A useful setting is
     '::0'.

--quiet
:    Suppress logging of questions and answers.

--server-id=*TEXT*
:    Return *TEXT* when queried for 'server.id' TXT, defaults to hostname.

--serve-rfc1918
:    On by default, this makes the server authoritatively aware of:
     10.in-addr.arpa, 168.192.in-addr.arpa and 16-31.172.in-addr.arpa, which
     saves load on the AS112 servers. Individual parts of these zones can still
     be loaded or forwarded.

--setgid=*GID*
:    If set, change group id to *GID* for more security.

--setuid=*UID*
:    If set, change user id to *UID* for more security.

--single-socket
:    If set, only use a single socket for outgoing queries.

--socket-dir=*DIRECTORY*
:    The controlsocket will live in *DIRECTORY*.

--spoof-nearmiss-max=*NUM*
:    If non-zero, assume spoofing after this many near misses.

--trace
:    if we should output heaps of logging.

--version-string=*TEXT*
:    *TEXT* will be reported on version.pdns or version.bind queries.

# BUGS
None known. File new ones at https://github.com/PowerDNS/pdns/issues.

# RESOURCES
Website: http://www.powerdns.com, https://github.com/PowerDNS/pdns

# SEE ALSO
rec_control(1)
