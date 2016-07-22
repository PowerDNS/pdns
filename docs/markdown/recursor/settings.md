# All PowerDNS Recursor Settings
Each setting can appear on the command line, prefixed by '--', or in the configuration file. The command line overrides the configuration file.

**Note**:  Settings marked as 'Boolean' can either be set to an empty value, which
means on, or to 'no' or 'off' which means off. Anything else means on.

So, as an example:

 * 'serve-rfc1918' on its own means: do serve those zones. 
 * 'serve-rfc1918=off' or 'serve-rfc1918=no' means: do not serve those zones. 
 * Anything else means: do serve those zones.

## `aaaa-additional-processing`
* Boolean
* Default: No
* Available until: 3.6.0

If turned on, the recursor will attempt to add AAAA IPv6 records to questions
for MX records and NS records. Can be quite slow as absence of these records in
earlier answers does not guarantee their non-existence. Can double the amount of
queries needed.

## `allow-from`
* IP ranges, separated by commas
* Default: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

Netmasks (both IPv4 and IPv6) that are allowed to use the server. The default
allows access only from RFC 1918 private IP addresses. Due to the aggressive
nature of the internet these days, it is highly recommended to not open up the
recursor for the entire internet. Questions from IP addresses not listed here
are ignored and do not get an answer.

## `allow-from-file`
* Path

Like [`allow-from`](#allow-from), except reading from file. Overrides the
[`allow-from`](#allow-from) setting. To use this feature, supply one netmask per
line, with optional comments preceded by a \#. Available since version 3.1.5.

## `any-to-tcp`
* Boolean
* Default: no

Answer questions for the ANY type on UDP with a truncated packet that refers the
remote server to TCP. Useful for mitigating ANY reflection attacks.

## `api-config-dir`
* Path
* Default: unset
* Available since: 4.0

Directory where the REST API stores its configuration and zones.

## `api-key`
* String
* Default: unset
* Available since: 4.0

Static pre-shared authentication key for access to the REST API.

## `api-readonly`
* Boolean
* Default: no
* Available since: 4.0

Disallow data modification through the REST API when set.

## `api-logfile`
* Path
* Default: unset
* Available since: 4.0

Location of the server logfile (used by the REST API).

## `auth-can-lower-ttl`
* Boolean
* Default: no
* Available until: 3.5

Authoritative zones can transmit a TTL value that is lower than that specified
in the parent zone. This is called a 'delegation inconsistency'. To follow
RFC 2181 paragraphs 5.2 and 5.4 to the letter, enable this feature. This will
mean a slight deterioration of performance, and it will not solve any problems,
but does make the recursor more standards compliant. Not recommended unless you
have to tick an 'RFC 2181 compliant' box.

## `auth-zones`
* Comma separated list of 'zonename=filename' pairs
* Available since: 3.1

Zones read from these files (in BIND format) are served authoritatively. Example:
`auth-zones=example.org=/var/zones/example.org, powerdns.com=/var/zones/powerdns.com`.

## `carbon-interval`
* Integer
* Default: 30
* Available since: 3.5.3

If sending carbon updates, this is the interval between them in seconds. See
["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome).

## `carbon-ourname`
* String
* Available since: 3.5.3

If sending carbon updates, if set, this will override our hostname. Be
careful not to include any dots in this setting, unless you know what you
are doing. See ["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome).

## `carbon-server`
* IP address
* Available since: 3.5.3

If set to an IP or IPv6 address, will send all available metrics to this server
via the carbon protocol, which is used by graphite and metronome. You may specify
an alternate port by appending :port, ex: 127.0.0.1:2004. See
["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome).

## `chroot`
* Path to a Directory
If set, chroot to this directory for more security. See [Security](../common/security.md).

Make sure that `/dev/log` is available from within the chroot. Logging will
silently fail over time otherwise (on logrotate).

When using `chroot`, all other paths (except for [`config-dir`](#config-dir) set
in the configuration are relative to the new root.

When using `chroot` and the API ([`webserver`](#webserver)), [`api-readonly`](#api-readonly)
must be set and [`api-config-dir`](#api-config-dir) unset.

## `client-tcp-timeout`
* Integer
* Default: 2

Time to wait for data from TCP clients.

## `config-dir`
* Path

Location of configuration directory (`recursor.conf`). Usually `/etc/powerdns`, but
this depends on `SYSCONFDIR` during compile-time.

## `config-name`
* String
* Default: unset

When running multiple recursors on the same server, read settings from
"name-recursor.conf", this will also rename the binary image.

## `daemon`
* Boolean
* Default: no (since 4.0.0, 'yes' before 4.0.0)

Operate in the background.

## `delegation-only`
* Domains, comma separated

Which domains we only accept delegations from (a Verisign special).

## `disable-packetcache`
* Boolean
* Default: no
* Available since: 3.2

Turn off the packet cache. Useful when running with Lua scripts that can not be
cached.

## `disable-syslog`
* Boolean
* Default: no

Do not log to syslog, only to stdout. Use this setting when running inside a
supervisor that handles logging (like systemd). **Note**: do not use this setting
in combination with [`daemon`](#daemon) as all logging will disappear.

## `dnssec`
* One of `off`, `process-no-validate`, `process`, `log-fail`, `validate`, String
* Default: `process-no-validate` (**note**: was `process` until 4.0.0-alpha2)
* Available since: 4.0.0

Set the mode for DNSSEC processing:

### `off`
No DNSSEC processing whatsoever. Ignore DO-bits in queries, don't request any
DNSSEC information from authoritative servers. This behaviour is similar to
PowerDNS Recursor pre-4.0.

### `process-no-validate`
Respond with DNSSEC records to clients that ask for it, set the DO bit on all
outgoing queries. Don't do any validation.

### `process`
Respond with DNSSEC records to clients that ask for it, set the DO bit on all
outgoing queries. Do validation for clients that request it (by means of the AD-
bit or DO-bit in the query).

### `log-fail`
Similar behaviour to `process`, but validate RRSIGs on responses and log bogus
responses.

#### `validate`
Full blown DNSSEC validation. Send SERVFAIL to clients on bogus responses.

## `dnssec-log-bogus`
* Boolean
* Default: no
* Available since: 4.0.0

Log every DNSSEC validation failure.
**Note**: This is not logged per-query but every time records are validated as Bogus.

## `dont-query`
* Netmasks, comma separated
* Default: 127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16,
  172.16.0.0/12, ::1/128, fc00::/7, fe80::/10, 0.0.0.0/8, 192.0.0.0/24,
  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, ::/96,
  ::ffff:0:0/96, 100::/64, 2001:db8::/32
* Available since: 3.1.5

The DNS is a public database, but sometimes contains delegations to private IP
addresses, like for example 127.0.0.1. This can have odd effects, depending on
your network, and may even be a security risk. Therefore, since version 3.1.5,
the PowerDNS recursor by default does not query private space IP addresses.
This setting can be used to expand or reduce the limitations.

## `edns-outgoing-bufsize`
* Integer
* Default: 1680

This is the value set for the EDNS0 buffer size in outgoing packets.
Lower this if you experience timeouts.

## `entropy-source`
* Path
* Default: /dev/urandom
* Available since: 3.1.5

PowerDNS can read entropy from a (hardware) source. This is used for generating
random numbers which are very hard to predict. Generally on UNIX platforms,
this source will be `/dev/urandom`, which will always supply random numbers,
even if entropy is lacking. Change to `/dev/random` if PowerDNS should block
waiting for enough entropy to arrive.

## `etc-hosts-file`
* Path
* Default: /etc/hosts

The path to the /etc/hosts file, or equivalent. This file can be used to serve
data authoritatively using [`export-etc-hosts`](#export-etc-hosts).

## `export-etc-hosts`
* Boolean
* Default: no
* Available since: 3.1

If set, this flag will export the host names and IP addresses mentioned in
`/etc/hosts`.

## `export-etc-hosts-search-suffix`
* String
* Available since: 3.4

If set, all hostnames in the [`export-etc-hosts`](#export-etc-hosts) file are
loaded in canonical form, based on this suffix, unless the name contains a '.',
in which case the name is unchanged. So an entry called 'pc' with
`export-etc-hosts-search-suffix='home.com'` will lead to the generation of
'pc.home.com' within the recursor. An entry called 'server1.home' will be stored
as 'server1.home', regardless of this setting.

## `fork`
* Boolean
* Default: no
* Available until: 3.2

If running on an SMP system with enough memory, this feature forks PowerDNS so
it benefits from two processors. Experimental. Renames controlsockets, so care
is needed to connect to the right one using `rec_control`, using `socket-pid`.
Available in versions of the Recursor before 3.2, replaced by the
['threads'](#threads) setting.

## `forward-zones`
* 'zonename=IP' pairs, comma separated
* Available since: 3.1

Queries for zones listed here will be forwarded to the IP address listed. i.e.
`forward-zones=example.org=203.0.113.210, powerdns.com=2001:DB8::BEEF:5`.

Since version 3.1.5, multiple IP addresses can be specified. Additionally, port
numbers other than 53 can be configured. Sample syntax:
`forward-zones=example.org=203.0.113.210:5300;127.0.0.1, powerdns.com=127.0.0.1;198.51.100.10:530;[2001:DB8::1:3]:5300`,
or on the command line:
`--forward-zones="example.org=203.0.113.210:5300;127.0.0.1, powerdns.com=127.0.0.1;9.8.7.6:530;[2001:DB8::1:3]:5300"`.

Forwarded queries have the 'recursion desired' bit set to 0, meaning that this
setting is intended to forward queries to authoritative servers.

## `forward-zones-file`
* Path
* Available since: 3.1.5

Same as [`forward-zones`](#forward-zones), parsed from a file. Only 1 zone is
allowed per line, specified as follows: `example.org=203.0.113.210, 192.0.2.4:5300`.

Since version 3.2, zones prefixed with a '+' are forwarded with the
recursion-desired bit set to one, for which see ['forward-zones-recurse'](#forward-zones-recurse).
Default behaviour without '+' is as with [`forward-zones`](#forward-zones).

Comments are allowed since version 4.0.0. Everything behind '#' is ignored.

## `forward-zones-recurse`
* 'zonename=IP' pairs, comma separated
* Available since: 3.2

Like regular [`forward-zones`](#forward-zones), but forwarded queries have the
'recursion desired' bit set to 1, meaning that this setting is intended to
forward queries to other recursive servers.

## `hint-file`
* Path
* Available since: 2.9.19

If set, the root-hints are read from this file. If unset, default root hints are
used.

## `include-dir`
* Path

Directory to scan for additional config files. All files that end with .conf are
loaded in order using `POSIX` as locale.

## `latency-statistic-size`
* Integer
* Default: 10000
* Available since 3.6

Indication of how many queries will be averaged to get the average latency
reported by the 'qa-latency' metric.

## `local-address`
* IP addresses, comma separated
* Default: 127.0.0.1

Local IPv4 or IPv6 addresses to bind to. Addresses can also contain port numbers,
for IPv4 specify like this: `192.0.2.4:5300`, for IPv6: `[::1]:5300`.
Port specifications are available since version 3.1.2.

**Warning**: When binding to wildcard addresses, UNIX semantics mean that
answers may not be sent from the address a query was received on. It is highly
recommended to bind to explicit addresses.

## `local-port`
* Integer
* Default: 53

Local port to bind to.

## `non-local-bind`
* Boolean
* Default: no
* Available since: 4.0.0

Bind to addresses even if one or more of the [`local-address`'s](#local-address)
do not exist on this server. Setting this option will enable the needed socket
options to allow binding to non-local addresses.
This feature is intended to facilitate ip-failover setups, but it may also
mask configuration issues and for this reason it is disabled by default.

## `loglevel`
* Integer between 0 and 
* Default: 4
* Available since: 3.6

Amount of logging. Higher is more, more logging may destroy performance.

## `log-common-errors`
* Boolean
* Default: no

Some DNS errors occur rather frequently and are no cause for alarm.

## `logging-facility`
* Integer
* Available since: 3.1.3

If set to a digit, logging is performed under this LOCAL facility. See
[Logging](../common/logging.md#logging). Do not pass names like 'local0'!

## `lowercase-outgoing`
* Boolean
* Default: no
* Available since: 4.0.0

Set to true to lowercase the outgoing queries. When set to 'no' (the default) a
query from a client using mixed case in the DNS labels (such as a user entering
mixed-case names or [draft-vixie-dnsext-dns0x20-00](http://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00)),
PowerDNS preserves the case of the query. Broken authoritative servers might give
a wrong or broken answer on this encoding. Setting `lowercase-outgoing` to 'yes'
makes the PowerDNS Recursor lowercase all the labels in the query to the authoritative
servers, but still return the proper case to the client requesting.

## `lua-config-file`
* Filename
* Available since 4.0.0

If set, and Lua support is compiled in, this will load an additional configuration file
for newer features and more complicated setups. 

### `addSortList`
Sortlist is a complicated feature which allows for the ordering of A and
AAAA records in answers to be modified, optionally dependently on who is
asking. Since clients frequently connect to the 'first' IP address they see,
this can effectively allow you to make sure that user from, say 10.0.0.0/8
also preferrably connect to servers in 10.0.0.0/8.

The syntax consists of a netmask for which this ordering instruction
applies, followed by a set of netmask (groups) which describe the desired
ordering. So an ordering instruction of "1.0.0.0/8", "2.0.0.0/8" will put
anything within 1/8 first, and anything in 2/8 second. Other IP addresses
would follow behind the addresses sorted earlier.

If netmasks are grouped, this means these get equal ordering.

`addSortList()` is intended to exactly mirror the semantics of the BIND
sortlist option, but the syntax is slightly different.

As an example, the following BIND sortlist:

```
{ 17.50.0.0/16; {17.238.240.0/24; 17.138.149.200;
{17.218.242.254; 17.218.252.254;}; 17.38.42.80;
17.208.240.100; }; };
```

Gets transformed into:

```
addSortList("17.50.0.0/16", {"17.238.240.0/24", "17.138.149.200",
{"17.218.242.254", "17.218.252.254"}, "17.38.42.80", 
"17.208.240.100" })
```

In other words: each IP address is put within quotes, and are separated by
commas instead of semicolons. For the rest everything is identical.

### Response Policy Zone (RPZ)
Response Policy Zone is an open standard developed by ISC, the authors of the BIND nameserver, to modify
DNS responses based on a policy loaded via a zonefile.

Frequently, Response Policy Zones get to be very large and change quickly,
so it is customary to update them over IXFR.
It allows the use of third-party feeds, and near real-time policy updates.

An RPZ can be loaded from file or slaved from a master. To load from file, use for example:

```
rpzFile("dblfilename", {defpol=Policy.Custom, defcontent="badserver.example.com"})
```

To slave from a master and start IXFR to get updates, use for example:

```
rpzMaster("192.0.2.4", "policy.rpz", {defpol=Policy.Drop})
```

In this example, 'policy.rpz' denotes the name of the zone to query for. 

Settings for `rpzFile` and `rpzMaster` can contain:

* defpol = Policy.Custom, Policy.Drop, Policy.NXDOMAIN, Policy.NODATA, Policy.Truncate, Policy.NoAction
* defcontent = CNAME field to return in case of defpol=Policy.Custom
* defttl = the TTL of the CNAME field to be synthesized. The default is to use the zone's TTL
* policyName = the name logged as 'appliedPolicy' in protobuf messages when this policy is applied

In addition to those, `rpzMaster` accepts:

* tsigname = the name of the TSIG key to authenticate to the server (also set tsigalgo, tsigsecret)
* tsigalgo = the name of the TSIG algorithm (like 'hmac-md5') used
* tsigsecret = base64 encoded TSIG secret
* refresh = an integer describing the interval between checks for updates. By default, the RPZ zone's default is used
* maxReceivedMBytes = the maximum size in megabytes of an AXFR/IXFR update, to prevent resource exhaustion.
The default value of 0 means no restriction.

If no settings are included, the RPZ is taken literally with no overrides applied.

The policy action are:

* Policy.Custom will return a NoError, CNAME answer with the value specified with `defcontent`
* Policy.Drop will simply cause the query to be dropped
* Policy.NoAction will continue normal processing of the query
* Policy.NODATA will return a NoError response with no value in the answer section
* Policy.NXDOMAIN will return a response with a NXDomain rcode
* Policy.Truncate will return a NoError, no answer, truncated response over UDP. Normal processing will continue over TCP

### Protocol Buffers (protobuf)
PowerDNS Recursor has the ability to emit a stream of protocol buffers messages over TCP,
containing information about queries, answers and policy decisions.

Messages contain the IP address of the client initiating the query,
the one on which the message was received, whether it was received over UDP or TCP,
a timestamp and the qname, qtype and qclass of the question.
In addition, messages related to responses contain the name, type, class
and rdata of A, AAAA and CNAME records present in the response, as well as the response
code.

Finally, if a RPZ or custom Lua policy has been applied, response messages
also contain the applied policy name and some tags. This is particularly useful
to detect and act on infected hosts.

Protobuf export to a server is enabled using the `protobufServer()` directive:

```
protobufServer("192.0.2.1:4242" [[[[[, timeout], maxQueuedEntries], reconnectWaitTime], maskV4], maskV6])
```

The optional parameters are:

* timeout = time in seconds to wait when sending a message, default to 2
* maxQueuedEntries = how many entries will be kept in memory if the server becomes unreachable, default to 100
* reconnectWaitTime = how long to wait, in seconds, between two reconnection attempts, default to 1
* maskV4 = network mask to apply to the client IPv4 addresses, for anonymization purpose. The default of 32 means no anonymization
* maskV6 = same as maskV4, but for IPv6. Default to 128

The protocol buffers message types can be found in the [`dnsmessage.proto`](https://github.com/PowerDNS/pdns/blob/master/pdns/dnsmessage.proto) file.

## `lua-dns-script`
* Path
* Default: unset

Path to a lua file to manipulate the recursor's answers. See [Scripting the
recursor](scripting.md).

## `max-cache-entries`
* Integer
* Default: 1000000

Maximum number of DNS cache entries. 1 million per thread will generally suffice
for most installations.

## `max-cache-ttl`
* Integer
* Default: 86400
* Available since: 3.2

Maximum number of seconds to cache an item in the DNS cache, no matter what the
original TTL specified.

## `max-mthreads`
* Integer
* Default: 2048

Maximum number of simultaneous MTasker threads.

## `max-packetcache-entries`
* Integer
* Default: 500000
* Available since: 3.2

Maximum number of Packet Cache entries. 1 million per thread will generally
suffice for most installations.

## `max-qperq`
* Integer
* Default: 50

The maximum number of outgoing queries that will be sent out during the resolution
of a single client query. This is used to limit endlessy chasing CNAME redirections.

## `max-negative-ttl`
* Integer
* Default: 3600

A query for which there is authoritatively no answer is cached to quickly deny a
record's existence later on, without putting a heavy load on the remote server.
In practice, caches can become saturated with hundreds of thousands of hosts
which are tried only once. This setting, which defaults to 3600 seconds, puts a
maximum on the amount of time negative entries are cached.

## `max-tcp-clients`
* Integer
* Default: 128

Maximum number of simultaneous incoming TCP connections allowed.

## `max-tcp-per-client`
* Integer
* Default: 0 (unlimited)

Maximum number of simultaneous incoming TCP connections allowed per client
(remote IP address).

## `max-total-msec`
* Integer
* Default: 7000

Total maximum number of miliseconds of wallclock time the servermay use to answer
a single query.

## `minimum-ttl-override`
* Integer
* Default: 0 (disabled)

This setting artificially raises all TTLs to be at least this long. While this
is a gross hack, and violates RFCs, under conditions of DoS, it may enable you
to continue serving your customers. Can be set at runtime using
`rec_control set-minimum-ttl 3600`.

## `network-timeout`
* Integer
* Default: 1500
* Available since: 3.2

Number of milliseconds to wait for a remote authoritative server to respond.

## `packetcache-ttl`
* Integer
* Default: 3600
* Available since: 3.2

Maximum number of seconds to cache an item in the packet cache, no matter what
the original TTL specified.

## `packetcache-servfail-ttl`
* Integer
* Default: 60
* Available since: 3.2

Maximum number of seconds to cache a 'server failure' answer in the packet cache.
From 4.0.0 onward, this settings maximum is capped to [`packetcache-ttl`](#packetcache-ttl).
i.e. setting `packetcache-ttl=15` and keeping `packetcache-servfail-ttl` at the
default will lower `packetcache-servfail-ttl` to `15`.

## `pdns-distributes-queries`
* Boolean
* Default: yes (since 3.7.0), no (before 3.7.0)
* Available since: 3.6

If set, PowerDNS will have only 1 thread listening on client sockets, and
distribute work by itself over threads. Improves performance on Linux. Do not
use on Recursor versions before 3.6 as the feature was experimental back then,
and not that stable.

## `query-local-address`
* IPv4 Address, comma separated
* Default: 0.0.0.0
* Available since: 3.2

Send out local queries from this address, or addresses, by adding multiple
addresses, increased spoofing resilience is achieved.

## `query-local-address6`
* IPv6 addresses, comma separated
* Default: unset
* Available since: 3.2

Send out local IPv6 queries from this address or addresses. Disabled by default,
which also disables outgoing IPv6 support.

## `quiet`
* Boolean
* Default: yes

Don't log queries.

## `root-nx-trust`
* Boolean
* Default: no (<= 4.0.0), yes

If set, an NXDOMAIN from the root-servers will serve as a blanket NXDOMAIN for the entire TLD
the query belonged to. The effect of this is far fewer queries to the root-servers.

## `security-poll-suffix`
* String
* Default: secpoll.powerdns.com.

Domain name from which to query security update notifications. Setting this to
an empty string disables secpoll.

## `serve-rfc1918`
* Boolean
* Default: yes

This makes the server authoritatively aware of: `10.in-addr.arpa`,
`168.192.in-addr.arpa`, `16-31.172.in-addr.arpa`, which saves load on the AS112
servers. Individual parts of these zones can still be loaded or forwarded.

## `server-down-max-fails`
* Integer
* Default: 64
* Available since: 3.6

If a server has not responded in any way this many times in a row, no longer
send it any queries for [`server-down-throttle-time`](#server-down-throttle-time)
seconds. Afterwards, we will try a new packet, and if that also gets no response
at all, we again throttle for [`server-down-throttle-time-seconds`](#server-down-throttle-time).
Even a single response packet will drop the block.

## `server-down-throttle-time`
* Integer
* Default: 60
* Available since: 3.6

Throttle a server that has failed to respond [`server-down-max-fails`](#server-down-max-fails)
times for this many seconds.

## `server-id`
* String
* Default: The hostname of the server

The PowerDNS recursor by replies to a query for 'id.server' with its hostname,
useful for in clusters. Use this setting to override the answer it gives.

Query example (where 192.0.2.14 is your server):
```
dig @192.0.2.14 CHAOS TXT id.server.
```

## `setgid`, `setuid`
* String
* Default: unset

PowerDNS can change its user and group id after binding to its socket. Can be
used for better [security](security.md).

## `single-socket`
* Boolean
* Default: no

Use only a single socket for outgoing queries.

## `socket-dir`
* Path

Where to store the control socket and pidfile. The default depends on
`LOCALSTATEDIR` during compile-time (usually `/var/run` or `/run`).

When using [`chroot`](#chroot) the default becomes to `/`.

## `socket-owner`, `socket-group`, `socket-mode`
Owner, group and mode of the controlsocket. Owner and group can be specified by
name, mode is in octal.

## `spoof-nearmiss-max`
* Integer
* Default: 20

If set to non-zero, PowerDNS will assume it is being spoofed after seeing this
many answers with the wrong id.

## `stack-size`
* Integer
* Default: 200000

Size of the stack per thread.

## `stats-ringbuffer-entries`
* Integer
* Default: 10000

Number of entries in the remotes ringbuffer, which keeps statistics on who is
querying your server. Can be read out using `rec_control top-remotes`.

## `threads`
* Integer
* Default: 2

Spawn this number of threads on startup.

## `trace`
* Boolean
* Default: no

If turned on, output impressive heaps of logging. May destroy performance under
load.

## `udp-truncation-threshold`
* Integer
* Default: 1680

EDNS0 allows for large UDP response datagrams, which can potentially raise
performance. Large responses however also have downsides in terms of reflection
attacks. This setting limits the accepted size. Maximum value is 65535, but
values above 4096 should probably not be attempted.

## `version`
Print version of this binary. Useful for checking which version of the PowerDNS
recursor is installed on a system. Available since version 3.1.5.

## `version-string`
* String
* Default: PowerDNS Recursor version number

By default, PowerDNS replies to the 'version.bind' query with its version number.
Security conscious users may wish to override the reply PowerDNS issues.

## `webserver`
* Boolean
* Default: no

Start the webserver (for REST API).

## `webserver-address`
* IP Addresses, separated by spaces
* Default: 127.0.0.1

IP address for the webserver to listen on.

## `webserver-allow-from`
* IP addresses, comma separated
* Default: 0.0.0.0, ::/0

These subnets are allowed to access the webserver.

## `webserver-password`
* String
* Default: unset

Password required to access the webserver.

## `webserver-port`
* Integer
* Default: 8082

TCP port where the webserver should listen on.

## `write-pid`
* Boolean
* Default: yes

If a PID file should be written. Available since 4.0.
