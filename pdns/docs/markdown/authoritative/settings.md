# All Authoritative Server settings
All PDNS Authoritative Server settings are listed here, excluding those that originate from backends, which are documented in the relevant chapters. These settings can be set inside `pdns.conf` or on the commandline when invoking the `pdns` binary.

You can use `+=` syntax to set some variables incrementally, but this requires you to have at least one non-incremental setting for the variable to act as base setting. This is mostly useful for `include-dir` directive.

For boolean settings, specifying the name of the setting without a value means `yes`.

## `allow-axfr-ips`
* IP ranges
* Default: 127.0.0.0/8,::1
Behaviour pre 2.9.10: When not allowing AXFR (disable-axfr), DO allow from these IP addresses or netmasks.

Behaviour post 2.9.10: If set, only these IP addresses or netmasks will be able to perform AXFR.

## `allow-dns-update-from`
* IP ranges
From 3.4 onward. Allow DNS updates from these IP ranges.

## `allow-recursion`
By specifying `allow-recursion`, recursion can be restricted to netmasks specified. The default is to allow recursion from everywhere. Example: `allow-recursion=192.168.0.0/24, 10.0.0.0/8, 192.0.2.4`.

## `also-notify`
When notifying a domain, also notify these nameservers. Example: `also-notify=192.168.0.1, 10.0.0.1`. The IP adresses listed in `also-notify` always receive a notification. Even if they do not match the list in `only-notify`.

## `any-to-tcp`
Boolean value (`yes` or `no`). Answer questions for the ANY and RRSIG types on UDP with a truncated packet that refers the remote server to TCP. Useful for mitigating reflection attacks. Defaults to `no`. Available since 3.3.

## `cache-ttl`
Seconds to store packets in the PacketCache. See ["Packet Cache"](#XXX).

## `carbon-ourname`
If sending carbon updates, if set, this will override our hostname. See ["PowerDNS Metrics"](#XXX "PowerDNS Metrics"). Available beyond 3.3.1.

## `carbon-server`
If set to an IP or IPv6 address, will send all available metrics to this server via the carbon protocol, which is used by graphite and metronome. See ["PowerDNS Metrics"](#XXX "PowerDNS Metrics"). Available beyond 3.3.1.

## `carbon-interval`
If sending carbon updates, this is the interval between them in seconds. See ["PowerDNS Metrics"](#XXX "PowerDNS Metrics"). Available beyond 3.3.1.

## `chroot`
If set, chroot to this directory for more security. See ["Security settings & considerations"](#XXX "Security settings & considerations").

## `config-dir`
Location of configuration directory (`pdns.conf`)

## `config-name`
Name of this virtual configuration - will rename the binary image. See ["Virtual hosting"](#XXX "Virtual hosting").

## `control-console`
Debugging switch - don't use.

## `daemon`
Operate as a daemon, boolean.

## `default-soa-name`
Name to insert in the SOA record if none set in the backend.

## `default-soa-mail`
Mail address to insert in the SOA record if none set in the backend.

## `default-ttl`
TTL to use when none is provided.

## `direct-dnskey`
Read additional ZSKs from the records table/your BIND zonefile.

## `disable-axfr`
Do not allow zone transfers. Before 2.9.10, this could be overridden by [`allow-axfr-ips`](#allow-axfr-ips).

## `disable-axfr-rectify`
Disable the rectify step during an outgoing AXFR. Only required for regression testing. Default is no.

## `disable-tcp`
Do not listen to TCP queries. Breaks RFC compliance.

## `distributor-threads`
Number of Distributor (backend) threads to start per receiver thread. See ["Authoritative Server Performance"](#XXX).

## `do-ipv6-additional-processing`
Perform AAAA additional processing.

## `edns-subnet-option-number`
Removed in 3.4. If edns-subnet-processing is enabled, this option allows the user to override the option number.

## `edns-subnet-processing`
Enables EDNS subnet processing, for backends that support it.

## `entropy-source`
Entropy source (like /dev/urandom).

## `experimental-api-readonly`
* Boolean
From 3.4 onward. Disallow data modification through the json API when set.

## `experimental-dname-processing`
Synthesise CNAME records from DNAME records as required. This approximately doubles query load. **Do not combine with DNSSEC!**

## `experimental-dnsupdate`
* Boolean
* Default: no
Enable/Disable DNS update (RFC2136) support.

## `fancy-records`
Process URL and MBOXFW records. See ["Fancy Records"](#XXX).

## `forward-dnsupdates`
* Boolean
* Default: no
Forward DNS updates sent to a slave to the master.

## `guardian`
Boolean, run within a guardian process. See ["Guardian"](#XXX).

## `help`
Provide a helpful message

## `include-dir`
Directory to scan for additional config files. All files that end with .conf are loaded in order.

## `launch`
Which backends to launch and order to query them in. See ["Modules & Backends"](#XXX).

## `lazy-recursion`
Boolean, on by default as of 2.1. Checks local data first before recursing. See ["Recursion"](#XXX). Removed in 3.2.

## `load-modules`
Load this module - supply absolute or relative path. See ["Modules & Backends"](#XXX).

## `local-address`
Local IP address to which we bind. You can specify multiple addresses separated by commas or whitespace. It is highly advised to bind to specific interfaces and not use the default 'bind to any'. This causes big problems if you have multiple IP addresses. Unix does not provide a way of figuring out what IP address a packet was sent to when binding to any.

## `local-address-nonexist-fail`
* Boolean
* Default: no
Fail to start if one or more of the local-address's do not exist on this server

## `local-ipv6`
Local IPv6 address to which we bind. You can specify multiple addresses separated by commas or whitespace.

## `local-ipv6-nonexist-fail`
* Boolean
* Default: no
Fail to start if one or more of the local-ipv6 addresses do not exist on this server.

## `local-port`
The port on which we listen. Only one port possible.

## `log-dns-details`
* Boolean
* Default: no
If set to 'no', informative-only DNS details will not even be sent to syslog, improving performance. Available from 2.5 and onwards.

## `logging-facility`
If set to a digit, logging is performed under this LOCAL facility. See ["Operational logging using syslog"](#XXX). Available from 1.99.9 and onwards. Do not pass names like 'local0'!

## `loglevel`
Amount of logging. Higher is more. Do not set below 3

## `log-dns-queries` [,`=no`]
Tell PowerDNS to log all incoming DNS queries. This will lead to a lot of logging! Only enable for debugging!

## `lua-prequery-script`
Lua script to run before answering a query. This is a feature used internally for regression testing. The API of this functionality is not guaranteed to be stable, and is in fact likely to change.

## `master` [,`=on`]
Turn on master support. Boolean.

## `max-cache-entries`
Maximum number of cache entries. 1 million will generally suffice for most installations. Available since version 2.9.22.

## `max-ent-entries`
Maximum number of empty non-terminals to add to a zone. This is a protection measure to avoid database explosion due to long names.

## `max-nsec3-iterations`
* Integer
* Default: 500
Limit the number of NSEC3 hash iterations

## `max-queue-length`
If this many packets are waiting for database attention, consider the situation hopeless and respawn.

## `max-signature-cache-entries`
* Integer
Maximum number of signatures cache entries

## `max-tcp-connections`
Allow this many incoming TCP DNS connections simultaneously.

## `module-dir`
Default directory for modules. See ["Modules and Backends"](#XXX).

## `negquery-cache-ttl`
| | |
|:-|:-|
|Type|Integer|
|Default|60|

Seconds to store queries with no answer in the Query Cache. See ["Query Cache"](performance.md#query-cache).

## `no-config`
Do not attempt to read the configuration file.

## `no-shuffle`
Do not attempt to shuffle query results.

## `overload-queue-length`
If this many packets are waiting for database attention, answer any new questions strictly from the packet cache.

## `reuseport`
Boolean, on Linux 3.9 and some BSD kernels the `SO\_REUSEPORT` option allows each receiver-thread to open a new socket on the same port which allows for much higher performance on multi-core boxes. Setting this option will enable use of `SO\_REUSEPORT` when available and seamlessly fall back to a single socket when it is not available. A side-effect is that you can start multiple servers on the same IP/port combination which may or may not be a good idea. You could use this to enable transparent restarts, but it may also mask configuration issues and for this reason it is disabled by default.

## `server-id`
This is the server ID that will be returned on an EDNS NSID query. Defaults to the host name.

## `only-notify`
Only send AXFR NOTIFY to these IP addresses or netmasks. The default is to notify the world. The IP addresses or netmasks in [`also-notify`](#also-notify) or ALSO-NOTIFY metadata always receive AXFR NOTIFY. Example (and default): `only-notify=0.0.0.0/0, ::/0`.

## `out-of-zone-additional-processing`
Boolean, do out of zone additional processing. This means that if a malicious user adds a '.com' zone to your server, it is not used for other domains and will not contaminate answers. Do not enable this setting if you run a public DNS service with untrusted users. Off by default.

## `pipebackend-abi-version`
ABI version to use for the pipe backend. See ["PipeBackend protocol"](backend-pipe.md#pipebackend-protocol).

## `prevent-self-notification`
Boolean, available as of 3.3. PowerDNS Authoritative Server attempts to not send out notifications to itself in master mode. In very complicated situations we could guess wrong and not notify a server that should be notified. In that case, set prevent-self-notification to "no".

## `query-cache-ttl`
| | |
|:-|:-|
|Type|Integer|
|Default|20|

Seconds to store queries with an answer in the Query Cache. See ["Query Cache"](performance.md#query-cache).

## `query-local-address`
The IP address to use as a source address for sending queries. Useful if you have multiple IPs and pdns is not bound to the IP address your operating system uses by default for outgoing packets.

## `query-local-address6`
Source IP address for sending IPv6 queries.

## `query-logging`
Boolean, hints to a backend that it should log a textual representation of queries it performs. Can be set at runtime.

## `queue-limit`
Maximum number of milliseconds to queue a query. See ["Authoritative Server Performance"](#XXX).

## `receiver-threads`
Number of receiver (listening) threads to start. See ["Authoritative Server Performance"](#XXX) for tuning details.

## `recursive-cache-ttl`
Seconds to store recursive packets in the PacketCache. See ["Packet Cache"](#XXX).

## `recursor`
If set, recursive queries will be handed to the recursor specified here. See ["Recursion"](#XXX).

## `retrieval-threads`
Number of AXFR slave threads to start.

## `send-root-referral`
Boolean or `lean`, if set, PowerDNS will send out old-fashioned root-referrals when queried for domains for which it is not authoritative. Wastes some bandwidth but may solve incoming query floods if domains are delegated to you for which you are not authoritative, but which are queried by broken recursors. Available since version 2.9.19.

Since version 2.9.21, it is possible to specify 'lean' root referrals, which waste less bandwidth.

## `setgid`
If set, change group id to this gid for more security. See ["Security settings & considerations"](#XXX).

## `setuid`
If set, change user id to this uid for more security. See ["Security settings & considerations"](#XXX).

## `slave`
Turn on slave support. Boolean.

## `slave-cycle-interval`
Schedule slave up-to-date checks of domains whose status is unknown every .. seconds.

## `slave-renotify`
Boolean, this setting will make PowerDNS renotify the slaves after an AXFR is *received* from a master. This is useful when using when running a signing-slave.

## `signing-threads`
Tell PowerDNS how many threads to use for signing. It might help improve signing speed by changing this number.

## `smtpredirector`
Our smtpredir MX host. See ["Fancy Records"](#XXX).

## `soa-expire-default`
604800 Default [SOA](#XXX) expire.

## `soa-minimum-ttl`
3600 Default [SOA](#XXX) minimum ttl.

## `soa-refresh-default`
10800 Default [SOA](#XXX) refresh.

## `soa-retry-default`
3600 Default [SOA](#XXX) retry.

## `soa-serial-offset`
If your database contains single-digit SOA serials and you need to host .DE domains, this setting can help placate their 6-digit SOA serial requirements. Suggested value is to set this to 1000000 which adds 1000000 to all SOA Serials under that offset.

## `socket-dir`
Where the controlsocket will live. See ["Controlsocket"](#XXX).

## `strict-rfc-axfrs`
Boolean, perform strictly RFC-conforming AXFRs, which are slow, but may be necessary to placate some old client tools.

## `tcp-control-address`
Address to bind to for TCP control.

## `tcp-control-port`
Port to bind to for TCP control.

## `tcp-control-range`
Limit TCP control to a specific client range.

## `tcp-control-secret`
Password for TCP control.

## `traceback-handler`
Enable the Linux-only traceback handler (default on).

## `trusted-notification-proxy`
IP address of incoming notification proxy

## `udp-truncation-threshold`
* Integer
* Default: 1680
EDNS0 allows for large UDP response datagrams, which can potentially raise performance. Large responses however also have downsides in terms of reflection attacks. Up till PowerDNS Authoritative Server 3.3, the truncation limit was set at 1680 bytes, regardless of EDNS0 buffer size indications from the client. Beyond 3.3, this setting makes our truncation limit configurable. Maximum value is 65535, but values above 4096 should probably not be attempted.

## `urlredirector`
Where we send hosts to that need to be url redirected. See ["Fancy Records"](#XXX).

## `version-string`
  * `anonymous`
  * `powerdns`
  * `full`
  * custom

When queried for its version over DNS (`dig chaos txt version.bind @pdns.ip.address`), PowerDNS normally responds truthfully. With this setting you can overrule what will be returned. Set the `version-string` to `full` to get the default behaviour, to `powerdns` to just make it state `served by PowerDNS - http://www.powerdns.com`. The `anonymous` setting will return a ServFail, much like Microsoft nameservers do. You can set this response to a custom value as well.

## `webserver`
* Boolean
* Default: no

Start a webserver for monitoring. See ["Performance Monitoring"](logging.md#performance-monitoring).

## `webserver-address`
* IP Address
* Default: 127.0.0.1
IP Address of webserver to listen on. See ["Performance Monitoring"](logging.md#performance-monitoring).

## `webserver-allow-from`
* IP ranges
Webserver access is only allowed from these subnets

## `webserver-password`
* String
* Default: unset
The plaintext password required for accessing the webserver. See ["Performance Monitoring"](logging.md#performance-monitoring).

## `webserver-port`
* Integer
* Default: 8001
The port where webserver to listen on. See ["Performance Monitoring"](logging.md#performance-monitoring).

## `webserver-print-arguments`
* Boolean
* Default: no
If the webserver should print arguments. See ["Performance Monitoring"](logging.md#performance-monitoring).

## `wildcard-url`
Check for wildcard URL records.
