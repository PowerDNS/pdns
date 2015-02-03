% REC_CONTROL(1)
% PowerDNS.COM BV
% April 2006

# NAME
rec_control - control pdns_recursor

# SYNOPSIS
**rec_control** [*OPTION*]... *COMMAND* [*COMMAND-OPTION*]...

DESCRIPTION
-----------
rec_control(1) allows the operator to control a running instance
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

--socket-dir=*PATH*
:    Where the controlsocket will live.

--socket-pid=*PID*
:    When running in SMP mode, pid of **pdns_recursor** to control.

--timeout=*NUM*
:    Number of seconds to wait for the remote PowerDNS Recursor to
     respond. Set to 0 for infinite.

# COMMANDS
current-queries
:    Shows the currently active queries.

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

reload-lua-script *FILENAME*
:    (Re)loads Lua script *FILENAME*.

reload-zones
:    Reload authoritative and forward zones. Retains current configuration
     in case of errors.

set-minimum-ttl *NUM*
:    Set minimum-ttl-override to *NUM*.

top-remotes
:    Shows the top-20 most active remote hosts. Statistics are over the
     last 'remotes-ringbuffer-entries' queries, which defaults to 0.

trace-regex *REGEX*
:    Emit resolution trace for matching queries. Empty regex to disable trace.

unload-lua-script
:    Unloads Lua script.

version
:    Report running version.

wipe-cache *DOMAIN* [*DOMAIN*] [...]
:    Wipe entries for *DOMAIN* from the cache. This is useful if, for example,
     an important server has a new IP address, but the TTL has not yet
     expired. Multiple domain names can be passed. Note that you must
     terminate a domain with a .!  So to wipe powerdns.org, issue
     'rec_control wipe-cache powerdns.org.'.
     Versions beyond 3.1 don't need the trailing dot. Consider not only
     wiping 'www.domain.com.' but also 'domain.com.', as the cached nameservers
     or target of CNAME may continue to be undesired.

# BUGS
None known. File new ones at https://github.com/PowerDNS/pdns/issues.

# RESOURCES
Website: http://wiki.powerdns.com, http://www.powerdns.com

# SEE ALSO
pdns_recursor(1)
