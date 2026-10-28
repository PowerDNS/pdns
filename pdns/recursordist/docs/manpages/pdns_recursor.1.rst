pdns_recursor
=============

Synopsis
--------
**pdns_recursor** [OPTION]...

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

    # rec_control quit-nicely

However, the recommended way of starting and stopping the recursor is to use
:manpage:`systemctl(1)` or the init.d script.

Options
-------
For authoritative listing of options, consult the online documentation
at `<https://doc.powerdns.com/>`

.. option:: --allow-from=<NETWORKS>

    If set, only allow these comma separated *NETWORKS*,
    with network mask to recurse. For example: 192.0.2.0/24,203.0.113.128/25.

.. option:: --auth-zones=<AUTHZONES>

    Where *AUTHZONES* is <ZONENAME>=<FILENAME>[,<ZONENAME>=<FILENAME>]...
    Serve *ZONENAME* from *FILENAME* authoritatively. For example::

      ds9a.nl=/var/zones/ds9a.nl,powerdns.com=/var/zones/powerdns.com.

.. option:: --chroot=<DIRECTORY>

    chroot the process to *DIRECTORY*.

.. option:: --client-tcp-timeout=<NUM>

    Timeout in seconds when talking to TCP clients.

.. option:: --config, --config=<OPTION>

    Show the current configuration. Since 4.8.0 there are three *OPTION* values:

    * ``--config=default`` to show the default configuration.
    * ``--config=diff``    show modified options in the current configuration.
    * ``--config=check``   to check the current configuration for errors.

.. option:: --config-dir=<DIRECTORY>

    Location of configuration directory (recursor.conf), the default
    depends on the SYSCONFDIR option at build-time, which is usually
    /etc/powerdns. The default can be found with
    ``pdns_recursor --config | grep ' config-dir='``.

.. option:: --daemon

    Operate as a daemon.

.. option:: --export-etc-hosts

    If set, this flag will export the hostnames and IP addresses
    mentioned in /etc/hosts.

.. option:: --forward-zones=<FORWARDZONES>

    Where *FORWARDZONES* is <ZONENAME>=<ADDRESS>[,<ZONENAME>=<ADDRESS>]...
    Queries for *ZONENAME* will be forwarded to *ADDRESS*. *ADDRESS*
    should be an IP address, not a hostname (to prevent chicken and egg
    problems). Example::

      forward-zones= ds9a.nl=213.244.168.210,powerdns.com=127.0.0.1.

.. option:: --forward-zones-file=<FILENAME>

    Similar to ``--forward-zones``, but read the options from *FILENAME*.
    *filename* should contain one zone per line, like::

      ds9a.nl=213.244.168.210.

.. option:: --help

    Show a summary of options.

.. option:: --hint-file=<FILENAME>

    Load root hints from this *FILENAME*

.. option:: --local-address=<ADDRESS>

    Listen on *ADDRESS*, separated by spaces or commas.
    Addresses specified can include port numbers; any which do not
    include port numbers will listen on *--local-port*.

.. option:: --local-port=<PORT>

    Listen on *PORT*.

.. option:: --log-common-errors

    If we should log rather common errors.

.. option:: --max-cache-entries=<NUM>

    Maximum number of entries in the main cache.

.. option:: --max-negative-ttl=<NUM>

    maximum number of seconds to keep a negative cached entry in memory.

.. option:: --max-tcp-clients=<NUM>

    Maximum number of simultaneous TCP clients.

.. option:: --max-tcp-per-client=<NUM>

    If set, maximum number of TCP sessions per client (IP address).

.. option:: --query-local-address=<ADDRESS[,ADDRESS]...>

    Use *ADDRESS* as Source IP address when sending queries.

.. option:: --quiet

    Suppress logging of questions and answers.

.. option:: --server-id=<TEXT>

    Return *TEXT* when queried for 'id.server' TXT, defaults to
    hostname.

.. option:: --serve-rfc1918

    On by default, this makes the server authoritatively aware of:
    10.in-addr.arpa, 168.192.in-addr.arpa and 16-31.172.in-addr.arpa,
    which saves load on the AS112 servers. Individual parts of these
    zones can still be loaded or forwarded.

.. option:: --setgid=<GID>

    If set, change group id to *GID* for more security.

.. option:: --setuid=<UID>

    If set, change user id to *UID* for more security.

.. option:: --single-socket

    If set, only use a single socket for outgoing queries.

.. option:: --socket-dir=<DIRECTORY>

    The controlsocket will live in *DIRECTORY*.

.. option:: --spoof-nearmiss-max=<NUM>

    If non-zero, assume spoofing after this many near misses.

.. option:: --trace

    if we should output heaps of logging.

.. option:: --version-string=<TEXT>

    *TEXT* WILL be reported on version.pdns or version.bind queries.

See also
--------
:manpage:`rec_control(1)`
:manpage:`systemctl(1)`
`<https://docs.powerdns.com/recursor>`__
