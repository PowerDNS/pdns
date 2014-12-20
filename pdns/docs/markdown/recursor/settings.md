# All PowerDNS Recursor Settings
Each setting can appear on the command line, prefixed by '--', or in the configuration file. The command line overrides the configuration file.

## `aaaa-additional-processing`
If turned on, the recursor will attempt to add AAAA IPv6 records to questions for MX records and NS records. Can be quite slow as absence of these records in earlier answers does not guarantee their non-existence. Can double the amount of queries needed. Off by default.

## `allow-from`
Comma separated netmasks (both IPv4 and IPv6) that are allowed to use the server. The default allows access only from RFC 1918 private IP addresses, like 10.0.0.0/8. Due to the aggressive nature of the internet these days, it is highly recommended to not open up the recursor for the entire internet. Questions from IP addresses not listed here are ignored and do not get an answer.

## `allow-from-file`
Like [`allow-from`](#allow-from), except reading from file. Overrides the [`allow-from`](#allow-from) setting. To use this feature, supply one netmask per line, with optional comments preceded by a \#. Available since version 3.1.5.

## `any-to-tcp`
Answer questions for the ANY type on UDP with a truncated packet that refers the remote server to TCP. Useful for mitigating ANY reflection attacks. Defaults to off.

## `auth-can-lower-ttl`
Authoritative zones can transmit a TTL value that is lower than that specified in the parent zone. This is called a 'delegation inconsistency'. To follow RFC 2181 paragraphs 5.2 and 5.4 to the letter, enable this feature. This will mean a slight deterioration of performance, and it will not solve any problems, but does make the recursor more standards compliant. Not recommended unless you have to tick an 'RFC 2181 compliant' box. Off by default.

## `auth-zones`
Comma separated list of 'zonename=filename' pairs. Zones read from these files (in BIND format) are served authoritatively. Example: `auth-zones=example.org=/var/zones/example.org, powerdns.com=/var/zones/powerdns.com`. Available since version 3.1.

## `carbon-ourname`
If sending carbon updates, if set, this will override our hostname. See ["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome). Available beyond 3.5.3.

## `carbon-server=...`
If set to an IP or IPv6 address, will send all available metrics to this server via the carbon protocol, which is used by graphite and metronome. See ["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome). Available beyond 3.5.3.

## `carbon-interval=...`
If sending carbon updates, this is the interval between them in seconds. See ["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome). Available beyond 3.5.3.

## `chroot`
If set, chroot to this directory for more security. See [Security](../common/security.md).

Make sure that `/dev/log` is available from within the chroot. Logging will silently fail over time otherwise (on logrotate).

## `client-tcp-timeout`
Time to wait for data from TCP clients. Defaults to 2 seconds.

## `config-dir`
Directory where the configuration file can be found.

## `daemon`
Operate in the background, which is the default.

## `delegation-only`
A Verisign special.

## `disable-packetcache`
Turn off the packet cache. Useful when running with Lua scripts that can not be cached. Available since version 3.2.

## `dont-query`
The DNS is a public database, but sometimes contains delegations to private IP addresses, like for example 127.0.0.1. This can have odd effects, depending on your network, and may even be a security risk. Therefore, since version 3.1.5, the PowerDNS recursor by default does not query private space IP addresses. This setting can be used to expand or reduce the limitations.

## `entropy-source`
From version 3.1.5 onwards, PowerDNS can read entropy from a (hardware) source. This is used for generating random numbers which are very hard to predict. Generally on UNIX platforms, this source will be `/dev/urandom`, which will always supply random numbers, even if entropy is lacking. Change to `/dev/random` if PowerDNS should block waiting for enough entropy to arrive.

## `export-etc-hosts`
If set, this flag will export the host names and IP addresses mentioned in `/etc/hosts`. Available since version 3.1.

## `export-etc-hosts-search-suffix`
If set, all hostnames in the export-etc-hosts file are loaded in canonical form, based on this suffix, unless the name contain a '.', in which case the name is unchanged. So an entry called 'pc' with export-etc-hosts-search-suffix='home.com' will lead to the generation of 'pc.home.com' within the recursor. An entry called 'server1.home' will be stored as 'server1.home', regardless of the export-etc-hosts setting. Available in since version 3.4.

## `fork`
If running on an SMP system with enough memory, this feature forks PowerDNS so it benefits from two processors. Experimental. Renames controlsockets, so care is needed to connect to the right one using `rec_control`, using `socket-pid`. Available in versions of the Recursor before 3.2, replaced by the 'threads' setting.

## `forward-zones`
Comma separated list of 'zonename=IP' pairs. Queries for zones listed here will be forwarded to the IP address listed. `forward-zones=example.org=203.0.113.210, powerdns.com=2001:DB8::BEEF:5`. Available since version 3.1.

Since version 3.1.5, multiple IP addresses can be specified. Additionally, port numbers other than 53 can be configured. Sample syntax: `forward-zones=example.org=203.0.113.210:5300;127.0.0.1, powerdns.com=127.0.0.1;198.51.100.10:530;[2001:DB8::1:3]:5300`, or on the command line: `--forward-zones="example.org=203.0.113.210:5300;127.0.0.1, powerdns.com=127.0.0.1;9.8.7.6:530;[2001:DB8::1:3]:5300"`.

Forwarded queries have the 'recursion desired' bit set to 0, meaning that this setting is intended to forward queries to authoritative servers.

## `forward-zones-file`
Same as [`forward-zones`](#forward-zones-file), parsed from a file. Only 1 zone is allowed per line, specified as follows: `example.org=203.0.113.210, 192.0.2.4:5300`. No comments are allowed. Available since version 3.1.5.

Since version 3.2, zones prefixed with a '+' are forwarded with the recursion-desired bit set to one, for which see 'forward-zones-recurse'. Default behaviour without '+' is as with [`forward-zones`](#forward-zones).

## `forward-zones-recurse`
Like regular 'forward-zones' (see above), but forwarded queries have the 'recursion desired' bit set to 1, meaning that this setting is intended to forward queries to authoritative servers or to resolving servers. Available since version 3.2.

## `hint-file`
If set, the root-hints are read from this file. If unset, default root hints are used. Available since version 2.9.19.

## `latency-statistic-size`
Indication of how many queries will be averaged to get the average latency reported by the 'qa-latency' metric. Since 3.6.

## `local-address`
Local IPv4 or IPv6 addresses to bind to, comma separated. Defaults to only loopback. Addresses can also contain port numbers, for IPv4 specify like this: `192.0.2.4:5300`, for IPv6: `[::1]:5300`. Port specifications are available since version 3.1.2.

**Warning**: When binding to wildcard addresses, UNIX semantics mean that answers may not be sent from the address a query was received on. It is highly recommended to bind to explicit addresses.

## `local-port`
Local port (singular) to bind to. Defaults to 53.

## `loglevel`
Amount of logging. Higher is more, more logging may destroy performance. Available since 3.6.

## `log-common-errors`
Some DNS errors occur rather frequently and are no cause for alarm. Logging these is on by default.

## `logging-facility`
If set to a digit, logging is performed under this LOCAL facility. See [Logging](../common/logging.md#logging). Available from 3.1.3 and onwards. Do not pass names like 'local0'!

## `max-cache-entries`
Maximum number of DNS cache entries. 1 million per thread will generally suffice for most installations.

## `max-packetcache-entries`
Maximum number of Packet Cache entries. 1 million per thread will generally suffice for most installations. Available since version 3.2.

## `max-cache-ttl`
Maximum number of seconds to cache an item in the DNS cache, no matter what the original TTL specified. Available since version 3.2.

## `max-negative-ttl`
A query for which there is authoritatively no answer is cached to quickly deny a record's existence later on, without putting a heavy load on the remote server. In practice, caches can become saturated with hundreds of thousands of hosts which are tried only once. This setting, which defaults to 3600 seconds, puts a maximum on the amount of time negative entries are cached.

## `max-tcp-clients`
Maximum number of simultaneous incoming TCP connections allowed. Defaults to 128. Available since version 2.9.18.

## `max-tcp-per-client`
Maximum number of simultaneous incoming TCP connections allowed per client (remote IP address). Defaults to 0, which means unlimited.

## `minimum-ttl-override`
Available since 3.6, this setting artificially raises all TTLs to be at least this long. While this is a gross hack, and violates RFCs, under conditions of DoS, it may enable you to continue serving your customers. Can be set at runtime using `rec_control set-minimum-ttl 3600`. To disable, set to 0 (the default).

## `network-timeout`
Number of milliseconds to wait for a remote authoritative server to respond. Defaults to 1500 msec, available since version 3.2.

## `packetcache-ttl`
Maximum number of seconds to cache an item in the packet cache, no matter what the original TTL specified. Available since version 3.2.

## `packetcache-servfail-ttl`
Maximum number of seconds to cache a 'server failure' answer in the packet cache. Available since version 3.2.

## `pdns-distributes-queries`
If set, PowerDNS will have only 1 thread listening on client sockets, and distribute work by itself over threads. Improves performance on Linux. Do not use on Recursor versions before 3.6 as the feature was experimental back then, and not that stable.

## `query-local-address`
Send out local queries from this address, or addresses. Since version 3.2, by adding multiple addresses, increased spoofing resilience is achieved. Addresses can be separated by a comma.

## `query-local-address6`
Send out local IPv6 queries from this address or addresses. Disabled by default, which also disables outgoing IPv6 support. Since version 3.2, multiple addresses can be specified, separated by a comma.

## `quiet`
Don't log queries. On by default.

## `remotes-ringbuffer-entries`
Number of entries in the remotes ringbuffer, which keeps statistics on who is querying your server. Can be read out using **rec\_control top-remotes**. Defaults to 0.

## `serve-rfc*1918*`
On by default, this makes the server authoritatively aware of: `10.in-addr.arpa`, `168.192.in-addr.arpa`, `16-31.172.in-addr.arpa`, which saves load on the AS112 servers. Individual parts of these zones can still be loaded or forwarded.

## `server-down-max-fails`, `server-down-throttle-time`
If a server has not responded in any way this many times in a row, no longer send it any queries for server-down-throttle-time seconds. Afterwards, we will try a new packet, and if that also gets no response at all, we again throttle for server-down-throttle-time-seconds. Even a single response packet will drop the block. Available and on by default since 3.6.

## `server-id`
The PowerDNS recursor by replies to a query for 'id.server' with its hostname, useful for in clusters. Use this setting to override the answer it gives.

setgid, setuid  
PowerDNS can change its user and group id after binding to its socket. Can be used for better security.

## `socket-dir`
Where to store the control socket. This option also works with the controller, **rec\_control**.

## `socket-owner`, `socket-group`, `socket-mode`
Owner, group and mode of the controlsocket. Owner and group can be specified by name, mode is in octal.

## `spoof-nearmiss-max`
If set to non-zero, PowerDNS will assume it is being spoofed after seeing this many answers with the wrong id. Defaults to 20.

## `trace`
If turned on, output impressive heaps of logging. May destroy performance under load.

## `udp-truncation-threshold=...`
EDNS0 allows for large UDP response datagrams, which can potentially raise performance. Large responses however also have downsides in terms of reflection attacks. This setting limits the accepted size. Maximum value is 65535, but values above 4096 should probably not be attempted. Default is 1680.

## `version`
Print version of this binary. Useful for checking which version of the PowerDNS recursor is installed on a system. Available since version 3.1.5.

## `version-string`
By default, PowerDNS replies to the 'version.bind' query with its version number. Security conscious users may wish to override the reply PowerDNS issues.
