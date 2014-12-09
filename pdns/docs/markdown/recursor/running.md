# Controlling and querying the recursor
To control and query the PowerDNS recursor, the tool `rec_control` is provided. This program talks to the recursor over the 'controlsocket', often stored in `/var/run`.

As a sample command, try:

``` {.screen}
# rec_control ping
pong
```

When not running as root, `--socket-dir=/tmp` might be appropriate.

## `rec_control` commands
dump-cache filename  
Dumps the entire cache to the filename mentioned. This file should not exist already, PowerDNS will refuse to overwrite it. While dumping, the recursor will not answer questions.

### `get statistic`
Retrieve a statistic. For items that can be queried, see below.

### `get-all`
Retrieve all statistics in one go. Available since version 3.2.

### `get-parameter parameter1 [parameter2 ..]`
Retrieve a configuration parameter. All parameters from the configuration and command line can be queried. Available since version 3.2.

### `ping`
Check if server is alive.

### `quit`
Request shutdown of the recursor.

### `reload-acls`
Reload access control lists.

### `reload-zones`
Reload data about all authoritative and forward zones. The configuration file is also scanned to see if the **auth-domain**, **forward-domain** and **export-etc-hosts** statements have changed, and if so, these changes are incorporated.

### `set-minimum-ttl`
Available since 3.6, this setting artificially raises all TTLs to be at least this long. While this is a gross hack, and violates RFCs, under conditions of DoS, it may enable you to continue serving your customers. Corresponds to the configuration file setting 'minimum-ttl-override'.

### `top-remotes`
Shows the top-20 most active remote hosts. Statistics are over the last **remotes-ringbuffer-entries** queries, which defaults to 0.

### `trace-regex regex`
Available since 3.5.

Queries matching this regular expression will generate voluminous tracing output. Be aware that matches from the packet cache will still not generate tracing. To unset the regex, pass `trace-regex` without a new regex.

The regular expression is matched against domain queries terminated with a `.`. So, for example the regex `powerdns\.com$` will not match a query for `www.powerdns.com`, since the attempted match will be with `www.powerdns.com.`.

In addition, since this is a regular expression, to exclusively match queries for `www.powerdns.com`, one should escape the dots: `^www\.powerdns\.com\.$`.

Multiple matches can be chained with the | operator. For example, to match all queries for Dutch (.nl) and German (.de) domain names, use: `\.nl\.$|\.de\.$`.

### `version`
Available after 3.6.1, report currently running version.

### `wipe-cache domain1. [domain2. ..]`
Wipe entries from the cache. This is useful if, for example, an important server has a new IP address, but the TTL has not yet expired. Multiple domain names can be passed. For versions before 3.1, you must terminate a domain with a `.`! So to wipe powerdns.org, issue `rec_control wipe-cache powerdns.org.`. For later versions, the dot is optional.

Note that deletion is exact, wiping `com.` will leave `www.powerdns.com.` untouched!

**Warning**: As of 3.1.7, this command also wipes the negative query cache for the specified domain.
**Warning**: Don't just wipe "www.somedomain.com", its NS records or CNAME target may still be undesired, so wipe "somedomain.com" as well.

The command `get` can query a large number of statistics, which are detailed in [Performance Monitoring](stats.md).

More details on what "throttled" queries and the like are can be found below in [Security Settings](security.md).
