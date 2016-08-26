% REC_CONTROL(1)
% PowerDNS.COM BV
% April 2006

# NAME
rec_control - control pdns_recursor

# SYNOPSIS
**rec_control** [*OPTION*]... *COMMAND* [*COMMAND-OPTION*]...

DESCRIPTION
-----------
**rec_control** allows the operator to control a running instance
of the pdns_recursor.

The commands that can be passed to the recursor are described on
http://doc.powerdns.com/md/recursor/running/\#rec_control-commands

# EXAMPLES
To stop the recursor by hand, run:

`# rec_control quit`

To dump the cache to disk, execute:

`# rec_control dump-cache /tmp/the-cache`

# OPTIONS
--help
:    provide this helpful message.

--config-dir=*PATH*
:    Directory where the recursor.conf lives.

--socket-dir=*PATH*
:    Where the controlsocket will live, please use **--config-dir** instead.

--socket-pid=*PID*
:    When running in SMP mode, pid of **pdns_recursor** to control.

--timeout=*NUM*
:    Number of seconds to wait for the remote PowerDNS Recursor to
     respond. Set to 0 for infinite.

# COMMANDS
add-nta *DOMAIN* [*REASON*]
:    Add a Negative Trust Anchor for *DOMAIN*, suffixed optionally with *REASON*.

add-ta *DOMAIN* *DSRECORD*
:    Add a Trust Anchor for *DOMAIN* with DS record data *DSRECORD*. This adds the
     new Trust Anchor to the existing set of Trust Anchors for *DOMAIN*.

current-queries
:    Shows the currently active queries.

clear-nta *DOMAIN*...
:    Remove Negative Trust Anchor for one or more *DOMAIN*s. Set domain to `'*'`
     to remove all NTA's.

clear-ta [*DOMAIN*]...
:    Remove Trust Anchor for one or more *DOMAIN*s. Note that removing the root
     trust anchor is not possible.

dump-cache *FILENAME*
:    Dumps the entire cache to *FILENAME*. This file should
     not exist already, PowerDNS will refuse to overwrite it. While
     dumping, the recursor will not answer questions.

dump-edns *FILENAME*
:    Dumps the EDNS status to the filename mentioned. This file should
     not exist already, PowerDNS will refuse to overwrite it. While
     dumping, the recursor will not answer questions.

dump-nsspeeds *FILENAME*
:    Dumps the nameserver speed statistics to the *FILENAME* mentioned.
     This file should not exist already, PowerDNS will refuse to 
     overwrite it. While dumping, the recursor will not answer questions.

get *STATISTIC* [*STATISTIC*]...
:    Retrieve a statistic. For items that can be queried, see
     http://doc.powerdns.com/md/recursor/stats/

get-all
:    Retrieve all known statistics.

get-ntas
:    Get a list of the currently configured Negative Trust Anchors.

get-tas
:    Get a list of the currently configured Trust Anchors.

get-parameter *KEY* [*KEY*]...
:    Retrieves the specified configuration parameter(s).

get-qtypelist
:    Retrieves QType statistics. Queries from cache aren't being counted yet.

help
:    Shows a list of supported commands.

ping
:    Check if server is alive.

quit
:    Request shutdown of the recursor.

quit-nicely
:    Request nice shutdown of the recursor.

reload-acls
:    Reloads ACLs.

reload-lua-script [*FILENAME*]
:    (Re)loads Lua script *FILENAME*. If *FILENAME* is empty, attempt to reload
     the currently loaded script. This replaces the script currently loaded.

reload-lua-config [*FILENAME*]
:    (Re)loads Lua configuration *FILENAME*. If *FILENAME* is empty, attempt to
     reload the currently loaded file. Note that *FILENAME* will be fully executed,
     any settings changed at runtime that are not modified in this file, will
     still be active. Reloading RPZ, especially by AXFR, can take some time; during
     which the recursor will not answer questions.

reload-zones
:    Reload authoritative and forward zones. Retains current configuration
     in case of errors.

set-carbon-server *CARBON SERVER* [*CARBON OURNAME*]
:    Set the carbon-server setting to *CARBON SERVER*. If *CARBON OURNAME* is not
     empty, also set the carbon-ourname setting to *CARBON OURNAME*.

set-dnssec-log-bogus *SETTING*
:    Set dnssec-log-bogus setting to *SETTING*. Set to 'on' or 'yes' to log DNSSEC
     validation failures and to 'no' or 'off' to disable logging these failures.

set-minimum-ttl *NUM*
:    Set minimum-ttl-override to *NUM*.

top-queries
:    Shows the top-20 queries. Statistics are over the last
     'stats-ringbuffer-entries' queries.

top-largeanswer-remotes
:    Shows the top-20 remote hosts causing large answers. Statistics are over the
     last 'stats-ringbuffer-entries' queries.

top-remotes
:    Shows the top-20 most active remote hosts. Statistics are over the
     last 'stats-ringbuffer-entries' queries.

top-servfail-queries
:    Shows the top-20 queries causing servfail responses. Statistics are
     over the last 'stats-ringbuffer-entries' queries.

top-servfail-remotes
:    Shows the top-20 most active remote hosts causing servfail responses.
     Statistics are over the last 'stats-ringbuffer-entries' queries.

trace-regex *REGEX*
:    Emit resolution trace for matching queries. Empty regex to disable trace.

unload-lua-script
:    Unloads Lua script.

version
:    Report running version.

wipe-cache *DOMAIN* [*DOMAIN*] [...]
:    Wipe entries for *DOMAIN* (exact name match) from the cache. This is useful
     if, for example, an important server has a new IP address, but the TTL has
     not yet expired. Multiple domain names can be passed. *DOMAIN* can be
     suffixed with a '$' to delete the whole tree from the cache. i.e. 'powerdns.com$'
     will remove all cached entries under and including the powerdns.com name.

# BUGS
None known. File new ones at https://github.com/PowerDNS/pdns/issues.

# RESOURCES
Website: https://docs.powerdns.com, https://www.powerdns.com

# SEE ALSO
pdns_recursor(1)
