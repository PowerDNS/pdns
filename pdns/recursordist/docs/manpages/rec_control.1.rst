rec_control
===========

Synopsis
--------

**rec_control** [*OPTION*]... *COMMAND* [*COMMAND-OPTION*]...

Description
-----------

:program:`rec_control` allows the operator to query and control a running
instance of the PowerDNS Recursor.

:program:`rec_control` talks to the recursor via a the 'controlsocket'. Which
is usually located in ``/var/run`` . The *--socket-dir* or the *--config-dir*
and *--config-name* switches control to which process :program:`rec_control`
connects.

Examples
--------
To see if the Recursor is alive, run::

  # rec_control ping

To stop the recursor by hand, run::

  # rec_control quit

To dump the caches to disk, execute::

  # rec_control dump-cache /tmp/the-cache

.. note::

  Before version 4.5.0, for each command that writes to a file, :program:`pdns_recursor` would open the file to write to.
  Starting with 4.5.0, the files are opened by the :program:`rec_control` command itself using the credentials and the current working directory of the user running :program:`rec_control`.
  A single minus *-* can be used as a filename to write the data to the standard output stream.

Options
-------
--help                provide this helpful message.
--config-dir=<path>   Directory where the recursor.conf lives.
--config-name=<name>  Name of the virtual configuration.
--socket-dir=<path>   Where the controlsocket will live, please
                      use **--config-dir** instead.
--socket-pid=<pid>    When running in SMP mode, pid of **pdns_recursor** to
                      control.
--timeout=<num>       Number of seconds to wait for the remote PowerDNS
                      Recursor to respond.
--version             Show the version number of this program. Note that the **version**
                      command shows the version of the running recursor.

Commands
--------
add-cookies-unsupported *IP* [*IP*...]
    Add non-expiring IPs of servers that do not support cookies to the cookie table.
    Optionally *IP:port* can be specified, the default is to use port 53.
    The listed addresses will be placed as ``Unsupported`` in the cookie support table and will not be pruned.

add-dont-throttle-names *NAME* [*NAME*...]
    Add names for nameserver domains that may not be throttled.

add-dont-throttle-netmasks *NETMASK* [*NETMASK*...]
    Add netmasks for nameservers that may not be throttled.

add-nta *DOMAIN* [*REASON*]
    Add a Negative Trust Anchor for *DOMAIN*, suffixed optionally with
    *REASON*.

add-ta *DOMAIN* *DSRECORD*
    Add a Trust Anchor for *DOMAIN* with DS record data *DSRECORD*. This adds
    the new Trust Anchor to the existing set of Trust Anchors for *DOMAIN*.

current-queries
    Shows the currently active queries.

clear-cookies [*IP*...]
    Remove entries from cookie table. If *IP* is ``*``, remove all.
    Optionally *IP:port* can be specified, the default is to use port 53.

clear-dont-throttle-names *NAME* [*NAME*...]
    Remove names that are not allowed to be throttled. If *NAME* is ``*``, remove all

clear-dont-throttle-netmasks *NETMASK* [*NETMASK*...]
    Remove netmasks that are not allowed to be throttled. If *NETMASK* is ``*``, remove all

clear-nta *DOMAIN*...
    Remove Negative Trust Anchor for one or more *DOMAIN*\ s. Set domain to
    ``*`` to remove all NTA's.

clear-ta [*DOMAIN*]...
    Remove Trust Anchor for one or more *DOMAIN*\ s. Note that removing the
    root trust anchor is not possible.

dump-cache *FILENAME* [*TYPE*...]
    Dumps caches to *FILENAME*. This file should not exist already,
    PowerDNS will refuse to overwrite it. While dumping, the recursor
    might not answer questions.

    If no *TYPE* is specified the record cache, the negative cache,
    the packet cache and the aggressive NSEC cache are dumped. To
    select specific caches specify one or more *TYPE*s, separated
    by spaces. The value of *TYPE* can be r, n, p or a.

dump-cookies *FILENAME*
    Dump the cookie store.

dump-dot-probe-map *FILENAME*
    Dump the contents of the DoT probe map to the *FILENAME* mentioned.

dump-edns *FILENAME*
    Dumps the EDNS status to the filename mentioned. This file should not exist
    already, PowerDNS will refuse to overwrite it. While dumping, the recursor
    will not answer questions.

dump-failedservers *FILENAME*
    Dump the contents of the failed server map to the *FILENAME* mentioned.
    This file should not exist already, PowerDNS will refuse to
    overwrite it otherwise. While dumping, the recursor will not answer
    questions.

dump-non-resolving *FILENAME*
    Dump the contents of the map of nameserver names that did not resolve to
    an address.  This file should not exist already, PowerDNS will
    refuse to overwrite it otherwise. While dumping, the recursor will
    not answer questions.

dump-nsspeeds *FILENAME*
    Dumps the nameserver speed statistics to the *FILENAME* mentioned. This
    file should not exist already, PowerDNS will refuse to overwrite it. While
    dumping, the recursor will not answer questions. Statistics are kept per
    thread, and the dumps end up in the same file.

dump-rpz *ZONE NAME* *FILE NAME*
    Dumps the content of the RPZ zone named *ZONE NAME* to the *FILENAME*
    mentioned. This file should not exist already, PowerDNS will refuse to
    overwrite it otherwise. While dumping, the recursor will not answer
    questions. For details on how RPZ are named see
    `<https://docs.powerdns.com/recursor/lua-config/rpz.html#policyname>`__.

dump-saved-parent-ns-sets *FILE NAME*
    Dump the entries of the map containing saved parent NS sets
    that were successfully used in resolving.
    The total number of entries is also printed in the header.
    An entry is saved if the recursor sees that the parent set includes
    names not in the child set. This is an indication of a
    misconfigured domain.

dump-throttlemap *FILENAME*
    Dump the contents of the throttle map to the *FILENAME* mentioned.
    This file should not exist already, PowerDNS will refuse to
    overwrite it otherwise. While dumping, the recursor will not answer
    questions.

get *STATISTIC* [*STATISTIC*]...
    Retrieve a statistic. For items that can be queried, see
    `<https://docs.powerdns.com/recursor/metrics.html>`__.

get-all
    Retrieve all known statistics.

get-dont-throttle-names
    Get the list of names that are not allowed to be throttled.

get-dont-throttle-netmasks
    Get the list of netmasks that are not allowed to be throttled.

get-ntas
    Get a list of the currently configured Negative Trust Anchors.

get-tas
    Get a list of the currently configured Trust Anchors.

get-parameter *KEY* [*KEY*]...
    Retrieves the specified configuration parameter(s).

get-proxymapping-stats
    Get the list of proxy-mapped subnets and associated counters.

get-qtypelist
    Retrieves QType statistics. Queries from cache aren't being counted yet.

get-remotelogger-stats
    Retrieves the remote logger statistics, per type and address.

hash-password [*WORK-FACTOR*]
    Asks for a password then returns the hashed and salted version,
    to use as a webserver password or API key. This command does
    not contact the recursor but does the hashing inside rec_control.
    An optional scrypt work factor can be specified, in power of two.
    The default is 1024.

help
    Shows a list of supported commands understood by the running
    :program:`pdns_recursor`.

list-dnssec-algos
    List supported (and potentially disabled) DNSSEC algorithms.

ping
    Check if server is alive.

quit
    Request shutdown of the recursor, exiting the process while
    letting the OS clean up resources.

quit-nicely
    Request nice shutdown of the recursor. This method allows all
    threads to finish their current work and releases resources before
    exiting. This is the preferred method to stop the recursor.

reload-acls
    Reloads ACLs.

reload-lua-script [*FILENAME*]
    (Re)loads Lua script *FILENAME*. If *FILENAME* is empty, attempt to reload
    the currently loaded script. This replaces the script currently loaded.

reload-lua-config [*FILENAME*]
    (Re)loads Lua configuration *FILENAME*. If *FILENAME* is empty, attempt
    to reload the currently loaded file. Note that *FILENAME* will be fully
    executed, any settings changed at runtime that are not modified in this
    file, will still be active. The effects of reloading do not always take
    place immediately, as some subsystems reload and replace configuration
    in an asynchronous way. If YAML settings are used this command will
    reload the runtime settable parts of the YAML settings.

reload-yaml
    Reload the runtime settable parts of the YAML settings.

reload-zones
    Reload authoritative and forward zones. Retains current configuration in
    case of errors.

set-carbon-server *CARBON SERVER* [*CARBON OURNAME*]
    Set the carbon-server setting to *CARBON SERVER*. If *CARBON OURNAME* is
    not empty, also set the carbon-ourname setting to *CARBON OURNAME*.

set-dnssec-log-bogus *SETTING*
    Set dnssec-log-bogus setting to *SETTING*. Set to ``on`` or ``yes`` to log
    DNSSEC validation failures and to ``no`` or ``off`` to disable logging these
    failures.

set-ecs-minimum-ttl *NUM*
    Set ecs-minimum-ttl-override to *NUM*.

set-max-aggr-nsec-cache-size *NUM*
    Change the maximum number of entries in the NSEC aggressive cache. If the
    cache is disabled by setting its size to 0 in the config, the cache size
    cannot be set by this command. Setting the size to 0 by this command still
    keeps the cache, but makes it mostly ineffective as it is emptied periodically.

set-max-cache-entries *NUM*
    Change the maximum number of entries in the DNS cache.  If reduced, the
    cache size will start shrinking to this number as part of the normal
    cache purging process, which might take a while.

set-max-packetcache-entries *NUM*
    Change the maximum number of entries in the packet cache.  If reduced, the
    cache size will start shrinking to this number as part of the normal
    cache purging process, which might take a while.

set-minimum-ttl *NUM*
    Set minimum-ttl-override to *NUM*.

set-event-trace-enabled *NUM*
    Set logging of event trace messages, ``0`` = disabled, ``1`` = protobuf,
    ``2`` = log file, ``3`` = protobuf and log file.

show-yaml [*FILE*]
    Show Yaml representation of old-style config.

top-queries
    Shows the top-20 queries. Statistics are over the last
    'stats-ringbuffer-entries' queries.

top-pub-queries
    Shows the top-20 queries grouped by public suffix list. Statistics are over
    the last 'stats-ringbuffer-entries' queries.

top-largeanswer-remotes
    Shows the top-20 remote hosts causing large answers. Statistics are over
    the last 'stats-ringbuffer-entries' queries.

top-remotes
    Shows the top-20 most active remote hosts. Statistics are over the last
    'stats-ringbuffer-entries' queries.

top-servfail-queries
    Shows the top-20 queries causing servfail responses. Statistics are over
    the last 'stats-ringbuffer-entries' queries.

top-bogus-queries
    Shows the top-20 queries causing bogus responses. Statistics are over
    the last 'stats-ringbuffer-entries' queries.

top-pub-servfail-queries
    Shows the top-20 queries causing servfail responses grouped by public
    suffix list. Statistics are over the last 'stats-ringbuffer-entries'
    queries.

top-pub-bogus-queries
    Shows the top-20 queries causing bogus responses grouped by public
    suffix list. Statistics are over the last 'stats-ringbuffer-entries'
    queries.

top-servfail-remotes
    Shows the top-20 most active remote hosts causing servfail responses.
    Statistics are over the last 'stats-ringbuffer-entries' queries.

top-bogus-remotes
    Shows the top-20 most active remote hosts causing bogus responses.
    Statistics are over the last 'stats-ringbuffer-entries' queries.

top-timeouts
    Shows the top-20 most active downstream timeout destinations.
    Statistics are over the last 'stats-ringbuffer-entries' queries.

trace-regex *REGEX* *FILE*
    Emit resolution trace for matching queries. No arguments disables tracing.
    Before version 4.9.0, there was no *FILE* argument, traces were always
    written to the log. Starting with version 4.9.0, trace information is
    written to the file specified, which may be ``-`` for the standard out
    stream.

    Queries matching this regular expression will generate voluminous tracing
    output. Be aware that matches from the packet cache will still not generate
    tracing. To unset the regex, pass **trace-regex** without a new regex.

    The regular expression is matched against domain queries terminated with a
    dot. For example the regex ``'powerdns.com$'`` will not match a query for
    ``'www.powerdns.com'``, since the attempted match will be with
    ``'www.powerdns.com.'``.

    In addition, since this is a regular expression, to exclusively match
    queries for ``'www.powerdns.com'``, one should escape the dots:
    ``'^www\.powerdns\.com\.$'``.
    Note that the single quotes prevent
    further interpretation of the backslashes by the shell.

    Multiple matches can be chained with the ``|`` operator. For example, to
    match all queries for Dutch (``.nl``) and German (``.de``) domain names, use:
    ``'\.nl\.$|\.de\.$'``.

unload-lua-script
    Unloads Lua script if one was loaded.

version
    Report the version of the running Recursor.

wipe-cache *DOMAIN* [*DOMAIN*] [...]
    Wipe entries for *DOMAIN* (exact name match) from the cache. This is useful
    if, for example, an important server has a new IP address, but the TTL has
    not yet expired. Multiple domain names can be passed.
    *DOMAIN* can be suffixed with a ``$``. to delete the whole tree from the
    cache. i.e. ``powerdns.com$`` will remove all cached entries under and
    including the powerdns.com name.

    **Note**: this command also wipes the negative cache.

    **Warning**: Don't just wipe "www.somedomain.com", its NS records or CNAME
    target may still be undesired, so wipe "somedomain.com" as well.

wipe-cache-typed *qtype* *DOMAIN* [*DOMAIN*] [...]
    Same as wipe-cache, but only wipe records of type *qtype*.

See also
--------
:manpage:`pdns_recursor(1)`
`<https://docs.powerdns.com/recursor>`__
