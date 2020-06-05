pdns_recursor
=============

Synopsis
--------
**pdns_recursor** [*OPTION*]...

Description
-----------
:program:`pdns_recursor` is a high performance, simple and secure recursing
nameserver. It currently powers hundreds of millions internet connections.

The recursor is configured via a configuration file, but each item in
that file can be overridden on the command line.

This manpage lists the core set of features needed to get the PowerDNS Recursor
working, for full and up to date details head to `<https://doc.powerdns.com/>`_.

Examples
--------
To listen on 192.0.2.53 and allow the 192.0.2.0/24 subnet to recurse, and run
as in the background, execute::

    # pdns_recursor --local-address=192.0.2.53 --allow-from=192.0.2.0/24 --daemon

To stop the recursor by hand, run::

    # rec_control quit

However, the recommended way of starting and stopping the recursor is to use
the init.d script or :manpage:`systemctl(1)`.

Options
-------
For authoritative listing of options, consult the online documentation
at `<https://doc.powerdns.com/>`

--allow-from=<networks>
    If set, only allow these comma separated *networks*,
    with network mask to recurse. For example: 192.0.2.0/24,203.0.113.128/25.
--auth-zones=<authzones>
    Where *authzone* is <zonename>=<filename>.
    Serve *zonename* from *filename* authoritatively. For example:
    ds9a.nl=/var/zones/ds9a.nl,powerdns.com=/var/zones/powerdns.com.
--chroot=<directory>
    chroot the process to *directory*.
--client-tcp-timeout=<num>
    Timeout in seconds when talking to TCP clients.
--config-dir=<directory>
    Location of configuration directory (recursor.conf), the default
    depends on the SYSCONFDIR option at build-time, which is usually
    /etc/powerdns. The default can be found with
    ``pdns_recursor --config | grep ' config-dir='``.
--daemon
    Operate as a daemon.
--delegation-only
    Which domains we only accept delegations from (a Verisign special).
--entropy-source=<file>
    Read new entropy from *file*, defaults to /dev/urandom.
--export-etc-hosts
    If set, this flag will export the hostnames and IP addresses
    mentioned in /etc/hosts.
--forward-zones=<forwardzones>
    Where *forwardzone* is <zonename>=<address>.
    Queries for *zonename* will be forwarded to *address*. *address*
    should be an IP address, not a hostname (to prevent chicken and egg
    problems). Example: forward-zones= ds9a.nl=213.244.168.210,
    powerdns.com=127.0.0.1.
--forward-zones-file=<filename>
    Similar to *--forward-zones*, but read the options from *filename*.
    *filename* should contain one zone per line, like:
    ds9a.nl=213.244.168.210.
--help
    Show a summary of options.
--hint-file=<filename>
    Load root hints from this *filename*
--local-address=<address>
    Listen on *address*, separated by spaces or commas.
    Addresses specified can include port numbers; any which do not
    include port numbers will listen on *--local-port*.
--local-port=<port>
    Listen on *port*.
--log-common-errors
    If we should log rather common errors.
--max-cache-entries=<num>
    Maximum number of entries in the main cache.
--max-negative-ttl=<num>
    maximum number of seconds to keep a negative cached entry in memory.
--max-tcp-clients=<num>
    Maximum number of simultaneous TCP clients.
--max-tcp-per-client=<num>
    If set, maximum number of TCP sessions per client (IP address).
--query-local-address=<address>[,address...]
    Use *address* as Source IP address when sending queries.
--quiet
    Suppress logging of questions and answers.
--server-id=<text>
    Return *text* WHen queried for 'id.server' TXT, defaults to
    hostname.
--serve-rfc1918
    On by default, this makes the server authoritatively aware of:
    10.in-addr.arpa, 168.192.in-addr.arpa and 16-31.172.in-addr.arpa,
    which saves load on the AS112 servers. Individual parts of these
    zones can still be loaded or forwarded.
--setgid=<gid>
    If set, change group id to *gid* for more security.
--setuid=<uid>
    If set, change user id to *uid* for more security.
--single-socket
    If set, only use a single socket for outgoing queries.
--socket-dir=<directory>
    The controlsocket will live in *directory*.
--spoof-nearmiss-max=<num>
    If non-zero, assume spoofing after this many near misses.
--trace
    if we should output heaps of logging.
--version-string=<text>
    *text* WILL be reported on version.pdns or version.bind queries.

See also
--------
:manpage:`rec_control(1)`
:manpage:`systemctl(1)`
