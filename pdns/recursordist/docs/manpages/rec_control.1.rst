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

To dump the cache to disk, execute::

  # rec_control dump-cache /tmp/the-cache

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
                      Recursor to respond. Set to 0 for infinite.

Commands
--------
add-dont-throttle-names NAME [NAME...]
    Add names for nameserver domains that may not be throttled.

add-dont-throttle-netmasks NETMASK [NETMASK...]
    Add netmasks for nameservers that may not be throttled.

add-nta *DOMAIN* [*REASON*]
    Add a Negative Trust Anchor for *DOMAIN*, suffixed optionally with
    *REASON*.

add-ta *DOMAIN* *DSRECORD*
    Add a Trust Anchor for *DOMAIN* with DS record data *DSRECORD*. This adds
    the new Trust Anchor to the existing set of Trust Anchors for *DOMAIN*.

current-queries
    Shows the currently active queries.

clear-dont-throttle-names NAME [NAME...]
    Remove names that are not allowed to be throttled. If *NAME* is '*', remove all

clear-dont-throttle-netmasks NETMASK [NETMASK...]
    Remove netmasks that are not allowed to be throttled. If *NETMASK* is '*', remove all

clear-nta *DOMAIN*...
    Remove Negative Trust Anchor for one or more *DOMAIN*\ s. Set domain to
    '*' to remove all NTA's.

clear-ta [*DOMAIN*]...
    Remove Trust Anchor for one or more *DOMAIN*\ s. Note that removing the
    root trust anchor is not possible.

dump-cache *FILENAME*
    Dumps the entire cache to *FILENAME*. This file should not exist already,
    PowerDNS will refuse to overwrite it. While dumping, the recursor will not
    answer questions.

    Typical PowerDNS Recursors run multiple threads, therefore you'll see
    duplicate, different entries for the same domains. The negative cache is
    also dumped to the same file. The per-thread positive and negative cache
    dumps are separated with an appropriate comment.

    .. note::

      :program:`pdns_recursor` often runs in a chroot. You can
      retrieve the file using::

        rec_control dump-cache /tmp/file
        mv /proc/$(pidof pdns_recursor)/root/tmp/file /tmp/filename

dump-edns *FILENAME*
    Dumps the EDNS status to the filename mentioned. This file should not exist
    already, PowerDNS will refuse to overwrite it. While dumping, the recursor
    will not answer questions.

    .. note::

      :program:`pdns_recursor` often runs in a chroot. You can
      retrieve the file using::

        rec_control dump-edns /tmp/file
        mv /proc/$(pidof pdns_recursor)/root/tmp/file /tmp/filename

dump-nsspeeds *FILENAME*
    Dumps the nameserver speed statistics to the *FILENAME* mentioned. This
    file should not exist already, PowerDNS will refuse to overwrite it. While
    dumping, the recursor will not answer questions. Statistics are kept per
    thread, and the dumps end up in the same file.

    .. note::

      :program:`pdns_recursor` often runs in a chroot. You can
      retrieve the file using::

        rec_control dump-nsspeeds /tmp/file
        mv /proc/$(pidof pdns_recursor)/root/tmp/file /tmp/filename

dump-rpz *ZONE NAME* *FILE NAME*
    Dumps the content of the RPZ zone named *ZONE NAME* to the *FILENAME*
    mentioned. This file should not exist already, PowerDNS will refuse to
    overwrite it otherwise. While dumping, the recursor will not answer
    questions.

    .. note::

      :program:`pdns_recursor` often runs in a chroot. You can
      retrieve the file using::

        rec_control dump-rpz ZONE_NAME /tmp/file
        mv /proc/$(pidof pdns_recursor)/root/tmp/file /tmp/filename

dump-throttlemap *FILENAME*
    Dump the contents of the throttle map to the *FILENAME* mentioned.
    This file should not exist already, PowerDNS will refuse to
    overwrite it otherwise. While dumping, the recursor will not answer
    questions.

    .. note::

      :program:`pdns_recursor` often runs in a chroot. You can
      retrieve the file using::

        rec_control dump-rpz ZONE_NAME /tmp/file
        mv /proc/$(pidof pdns_recursor)/root/tmp/file /tmp/filename

get *STATISTIC* [*STATISTIC*]...
    Retrieve a statistic. For items that can be queried, see
    :doc:`../metrics`

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

get-qtypelist
    Retrieves QType statistics. Queries from cache aren't being counted yet.

help
    Shows a list of supported commands understood by the running
    :program:`pdns_recursor`

ping
    Check if server is alive.

quit
    Request shutdown of the recursor.

quit-nicely
    Request nice shutdown of the recursor.

reload-acls
    Reloads ACLs.

reload-lua-script [*FILENAME*]
    (Re)loads Lua script *FILENAME*. If *FILENAME* is empty, attempt to reload
    the currently loaded script. This replaces the script currently loaded.

reload-lua-config [*FILENAME*]
    (Re)loads Lua configuration *FILENAME*. If *FILENAME* is empty, attempt
    to reload the currently loaded file. Note that *FILENAME* will be fully
    executed, any settings changed at runtime that are not modified in this
    file, will still be active. Reloading RPZ, especially by AXFR, can take
    some time; during which the recursor will not answer questions.

reload-zones
    Reload authoritative and forward zones. Retains current configuration in
    case of errors.

set-carbon-server *CARBON SERVER* [*CARBON OURNAME*]
    Set the carbon-server setting to *CARBON SERVER*. If *CARBON OURNAME* is
    not empty, also set the carbon-ourname setting to *CARBON OURNAME*.

set-dnssec-log-bogus *SETTING*
    Set dnssec-log-bogus setting to *SETTING*. Set to 'on' or 'yes' to log
    DNSSEC validation failures and to 'no' or 'off' to disable logging these
    failures.

set-ecs-minimum-ttl *NUM*
    Set ecs-minimum-ttl-override to *NUM*.

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

trace-regex *REGEX*
    Emit resolution trace for matching queries. Empty regex to disable trace.

    Queries matching this regular expression will generate voluminous tracing
    output. Be aware that matches from the packet cache will still not generate
    tracing. To unset the regex, pass **trace-regex** without a new regex.

    The regular expression is matched against domain queries terminated with a
    '.'. For example the regex 'powerdns\.com$' will not match a query for
    'www.powerdns.com', since the attempted match will be with
    'www.powerdns.com.'.

    In addition, since this is a regular expression, to exclusively match
    queries for 'www.powerdns.com', one should escape the dots:
    '^www\.powerdns\.com\.$'.

    Multiple matches can be chained with the '|' operator. For example, to
    match all queries for Dutch (.nl) and German (.de) domain names, use:
    '\.nl\.$|\.de\.$'.

unload-lua-script
    Unloads Lua script if one was loaded.

version
    Report running version.

wipe-cache *DOMAIN* [*DOMAIN*] [...]
    Wipe entries for *DOMAIN* (exact name match) from the cache. This is useful
    if, for example, an important server has a new IP address, but the TTL has
    not yet expired. Multiple domain names can be passed.
    *DOMAIN* can be suffixed with a '$'. to delete the whole tree from the
    cache. i.e. 'powerdns.com$' will remove all cached entries under and
    including the powerdns.com name.

    **Note**: this command also wipes the negative cache.

    **Warning**: Don't just wipe "www.somedomain.com", its NS records or CNAME
    target may still be undesired, so wipe "somedomain.com" as well.

See also
--------
:manpage:`pdns_recursor(1)`
