# All Authoritative Server settings
All PowerDNS Authoritative Server settings are listed here, excluding those that
originate from backends, which are documented in the relevant chapters. These
settings can be set inside `pdns.conf` or on the commandline when invoking the
`pdns` binary.

You can use `+=` syntax to set some variables incrementally, but this requires
you to have at least one non-incremental setting for the variable to act as base
setting. This is mostly useful for [`include-dir`](#include-dir) directive.

For boolean settings, specifying the name of the setting without a value means
`yes`.

## `8bit-dns`
* Allow 8 bit dns queries
* Default: no
* Available since: 4.0.0

Allow 8 bit DNS queries.

## `allow-axfr-ips`
* IP ranges, separated by commas
* Default: 127.0.0.0/8,::1

If set, only these IP addresses or netmasks will be able to perform AXFR.

## `allow-dnsupdate-from`
* IP ranges, separated by commas

Allow DNS updates from these IP ranges.

## `allow-notify-from`
* IP ranges, separated by commas
* Default: 0.0.0.0/0,::/0
* Available since: 3.5.0

Allow AXFR NOTIFY from these IP ranges.
Setting this to an empty string will drop all incoming notifies.

## `allow-unsigned-notify`
* Boolean
* Default: yes
* Available since: 4.0

Turning this off requires all notifications that are received to be signed by valid TSIG signature for the zone.

## `allow-unsigned-supermaster`
* Boolean
* Default: yes
* Available since: 4.0

Turning this off requires all supermaster notifications to be signed by valid TSIG signature. It will accept any existing key on slave.

## `allow-recursion`
* IP ranges, separated by commas
* Default: 0.0.0.0/0
* Removed in: 4.1.0

By specifying `allow-recursion`, recursion can be restricted to netmasks
specified. The default is to allow recursion from everywhere. Example:
`allow-recursion=198.51.100.0/24, 10.0.0.0/8, 192.0.2.4`.

## `also-notify`
* IP addresses, separated by commas

When notifying a domain, also notify these nameservers. Example:
`also-notify=192.0.2.1, 203.0.113.167`. The IP addresses listed in `also-notify`
always receive a notification. Even if they do not match the list in
[`only-notify`](#also-notify).

## `any-to-tcp`
* Boolean
* Default: yes (no, in <= 4.0.1)
* Available since: 3.3

Answer questions for the ANY on UDP with a truncated packet that refers the
remote server to TCP. Useful for mitigating reflection attacks.

## `api`
* Boolean
* Default: no
* Available since: 4.0

Enable/disable the [REST API](../httpapi/README.md).

## `api-key`
* String
* Available since: 4.0

Static pre-shared authentication key for access to the REST API.

## `api-readonly`
* Boolean
* Default: no
* Available since: 4.0

Disallow data modification through the REST API when set.

## `axfr-lower-serial`
* Boolean
* Default: no
* Available since: 4.0.4

Also AXFR a zone from a master with a lower serial.

## `cache-ttl`
* Integer
* Default: 20

Seconds to store packets in the PacketCache. See
["Packet Cache"](performance.md#packet-cache).

## `carbon-ourname`

* String
* Default: the hostname of the server
* Available since: 3.3.1

If sending carbon updates, if set, this will override our hostname. Be careful not to include any dots in this setting, unless you know what you are doing. See
["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome).

## `carbon-server`
* IP Address
* Available since: 3.3.1

Send all available metrics to this server via the carbon protocol, which is used
by graphite and metronome. It has to be an address (no hostnames). 
You may specify an alternate port by appending :port, 
ex: 127.0.0.1:2004. See 
["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome).

## `carbon-interval`
* Integer
* Default: 30
* Available since: 3.3.1

If sending carbon updates, this is the interval between them in seconds. See
["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome).

## `chroot`
* Path

If set, chroot to this directory for more security. See
["Security settings & considerations"](../common/security.md).

Make sure that `/dev/log` is available from within the chroot. Logging will
silently fail over time otherwise (on logrotate).

When setting `chroot`, all other paths in the config (except for
[`config-dir`](#config-dir) and [`module-dir`](#module-dir)) set in the configuration
are relative to the new root.

When running on a system where systemd manages services, `chroot` does not work out of the box, as PowerDNS cannot use the `NOTIFY_SOCKET`.
Either don't `chroot` on these systems or set the 'Type' of the this service to 'simple' instead of 'notify' (refer to the systemd documentation on how to modify unit-files)

## `config-dir`
* Path

Location of configuration directory (`pdns.conf`). Usually `/etc/powerdns`, but
this depends on `SYSCONFDIR` during compile-time.

## `config-name`
* String

Name of this virtual configuration - will rename the binary image. See
["Virtual hosting"](running.md#virtual-hosting).

## `control-console`
Debugging switch - don't use.

## `daemon`
* Boolean
* Default: no

Operate as a daemon.

## `default-ksk-algorithms`
* String
* Default: ecdsa256

The algorithm that should be used for the KSK when running
[`pdnsutil secure-zone`](../manpages/pdnsutil.1.md).
Must be one of:
* rsamd5
* dh
* dsa
* ecc
* rsasha1
* rsasha256
* rsasha512
* ecc-gost
* ecdsa256 (ECDSA P-256 with SHA256)
* ecdsa384 (ECDSA P-384 with SHA384)
* ed25519

## `default-ksk-size`
* Integer
* Default: whichever is default for `default-ksk-algorithms`

The default keysize for the KSK generated with
[`pdnsutil secure-zone`](../manpages/pdnsutil.1.md).

## `default-soa-name`
* String
* Default: a.misconfigured.powerdns.server

Name to insert in the SOA record if none set in the backend.

## `default-soa-edit`
* String
* Default: empty
* Available since: 3.4.7

Use this soa-edit value for all zones if no [`SOA-EDIT`](domainmetadata.md#SOA-EDIT) metadata value is set.

## `default-soa-edit-signed`
* String
* Default: empty
* Available since: 3.4.7

Use this soa-edit value for all signed zones if no [`SOA-EDIT`](domainmetadata.md#SOA-EDIT) metadata value is set. Overrides [`default-soa-edit`](#default-soa-edit)

## `default-soa-mail`
* String

Mail address to insert in the SOA record if none set in the backend.

## `default-ttl`
* Integer
* Default: 3600

TTL to use when none is provided.

## `default-zsk-algorithms`
* String
* Default: (empty)

The algorithm that should be used for the ZSK when running
[`pdnsutil secure-zone`](../manpages/pdnsutil.1.md).
Must be one of:
* rsamd5
* dh
* dsa
* ecc
* rsasha1
* rsasha256
* rsasha512
* ecc-gost
* ecdsa256 (ECDSA P-256 with SHA256)
* ecdsa384 (ECDSA P-384 with SHA384)
* ed25519

## `default-zsk-size`
* Integer
* Default: whichever is default for `default-zsk-algorithms`

The default keysize for the ZSK generated with
[`pdnsutil secure-zone`](../manpages/pdnsutil.1.md).

## `direct-dnskey`
* Boolean
* Default: no

Read additional ZSKs from the records table/your BIND zonefile. If not set,
DNSKEY records in the zonefiles are ignored.

## `disable-axfr`
* Boolean
* Default: no

Do not allow zone transfers.

## `disable-axfr-rectify`
* Boolean
* Default: no

Disable the rectify step during an outgoing AXFR. Only required for regression
testing.

## `disable-syslog`
* Boolean
* Default: no

Do not log to syslog, only to stdout. Use this setting when running inside a
supervisor that handles logging (like systemd). **Note**: do not use this setting
in combination with [`daemon`](#daemon) as all logging will disappear.

## `disable-tcp`
* Boolean
* Default: no

Do not listen to TCP queries. Breaks RFC compliance.

## `distributor-threads`
* Integer
* Default: 3

Number of Distributor (backend) threads to start per receiver thread. See
["Authoritative Server Performance"](performance.md).

## `dname-processing`
* Boolean
* Default: no

Synthesise CNAME records from DNAME records as required. This approximately
doubles query load. **Do not combine with DNSSEC!**

## `dnssec-key-cache-ttl`
* Integer
* Default: 30

Seconds to cache DNSSEC keys from the database. A value of 0 disables caching.

## `dnsupdate`
* Boolean
* Default: no

Enable/Disable DNS update (RFC2136) support.

## `do-ipv6-additional-processing`
* Boolean
* Default: yes

Perform AAAA additional processing. This sends AAAA records in the ADDITIONAL
section when sending a referral.

## `domain-metadata-cache-ttl`
* Integer
* Default: 60

Seconds to cache domain metadata from the database. A value of 0 disables caching.

## `edns-subnet-processing`
* Boolean
* Default: no

Enables EDNS subnet processing, for backends that support it.

## `entropy-source`
* Path
* Default: /dev/urandom

Entropy source file to use.

## `expand-alias`
* Boolean
* Default: no
* Since: 4.1.0

If this is enabled, ALIAS records are expanded (synthesised to their A/AAAA).

If this is disabled (the default), ALIAS records will not expanded and the server will will return NODATA for A/AAAA queries for such names.

**note**: [`resolver`](#resolver) must also be set for ALIAS expansion to work!

**note**: In PowerDNS Authoritative Server 4.0.x, this setting did not exist and ALIAS was always expanded.

## `forward-dnsupdate`
* Boolean
* Default: no

Forward DNS updates sent to a slave to the master.

## `guardian`
* Boolean
* Default: no

Run within a guardian process. See ["Guardian"](running.md#guardian).

## `include-dir`
* Path

Directory to scan for additional config files. All files that end with .conf are
loaded in order using `POSIX` as locale.

## `launch`
* Backend names, separated by commas

Which backends to launch and order to query them in. Launches backends. In its
most simple form, supply all backends that need to be launched. e.g.

```
launch=bind,gmysql,remote
```

If you find that you need to query a backend multiple times with different configuration,
you can specify a name for later instantiations. e.g.:

```
launch=gmysql,gmysql:server2
```

In this case, there are 2 instances of the gmysql backend, one by the normal name
and the second one is called 'server2'. The backend configuration item names
change: e.g. `gmysql-host` is available to configure the `host` setting of the
first or main instance, and `gmysql-server2-host` for the second one.

## `load-modules`
* Paths, separated by commas

If backends are available in nonstandard directories, specify their location here.
Multiple files can be loaded if separated by commas. Only available in non-static
distributions.

## `local-address`
* IPv4 Addresses, separated by commas or whitespace
* Default: 0.0.0.0

Local IP address to which we bind. It is highly advised to bind to specific
interfaces and not use the default 'bind to any'. This causes big problems if
you have multiple IP addresses. Unix does not provide a way of figuring out what
IP address a packet was sent to when binding to any.

## `non-local-bind`
* Boolean
* Default: no

Bind to addresses even if one or more of the [`local-address`'s](#local-address)
do not exist on this server. Setting this option will enable the needed socket
options to allow binding to non-local addresses.
This feature is intended to facilitate ip-failover setups, but it may also
mask configuration issues and for this reason it is disabled by default.

## `lua-axfr-script`

* String
* Default: empty
* Available since: 4.0.4

Script to be used to edit incoming AXFRs, see [Modifying a slave zone using a script](modes-of-operation.md#modifying-a-slave-zone-using-a-script).

## `local-address-nonexist-fail`
* Boolean
* Default: no

Fail to start if one or more of the [`local-address`'s](#local-address) do not
exist on this server.

## `local-ipv6`
* IPv6 Addresses, separated by commas or whitespace
* Default: ::

Local IPv6 address to which we bind. It is highly advised to bind to specific
interfaces and not use the default 'bind to any'. This causes big problems if
you have multiple IP addresses.

## `local-ipv6-nonexist-fail`
* Boolean
* Default: no

Fail to start if one or more of the [`local-ipv6`](#local-ipv6) addresses do not
exist on this server.

## `local-port`
* Integer
* Default: 53

The port on which we listen. Only one port possible.

## `log-dns-details`
* Boolean
* Default: no

If set to 'no', informative-only DNS details will not even be sent to syslog,
improving performance. Available from 2.5 and onwards.

## `logging-facility`
If set to a digit, logging is performed under this LOCAL facility. See
["Operational logging using syslog"](../common/logging.md#logging).
Available from 1.99.9 and onwards. Do not pass names like 'local0'!

## `loglevel`
* Integer
* Default: 4

Amount of logging. Higher is more. Do not set below 3

## `log-dns-queries`
* Boolean
* Default: no

Tell PowerDNS to log all incoming DNS queries. This will lead to a lot of
logging! Only enable for debugging! Set [`loglevel`](#loglevel) to at least 5
to see the logs.

## `lua-prequery-script`
* Path

Lua script to run before answering a query. This is a feature used internally
for regression testing. The API of this functionality is not guaranteed to be
stable, and is in fact likely to change.

## `master`
* Boolean
* Default: no

Turn on master support. See ["Modes of operation"](modes-of-operation.md#master-operation).

## `max-cache-entries`
* Integer
* Default: 1000000

Maximum number of entries in the query cache. 1 million (the default) will generally suffice
for most installations. Starting with 4.1, the packet and query caches are distinct so you might
also want to see `max-packet-cache-entries`.

## `max-ent-entries`
* Integer
* Default: 100000

Maximum number of empty non-terminals to add to a zone. This is a protection
measure to avoid database explosion due to long names.

## `max-nsec3-iterations`
* Integer
* Default: 500

Limit the number of NSEC3 hash iterations

## `max-packet-cache-entries`
* Integer
* Default: 1000000

Maximum number of entries in the packet cache. 1 million (the default) will generally suffice
for most installations. This setting has been introduced in 4.1, previous used the `max-cache-entries`
setting for both the packet and query caches.

## `max-queue-length`
* Integer
* Default: 5000

If this many packets are waiting for database attention, consider the situation
hopeless and respawn.

## `max-signature-cache-entries`
* Integer
* Default: 2^64 (on 64-bit systems)

Maximum number of signatures cache entries

## `max-tcp-connection-duration`
* Integer
* Default: 0

Maximum time in seconds that a TCP DNS connection is allowed to stay open.
0 means unlimited.
Note that exchanges related to an AXFR or IXFR are not affected by this setting.

## `max-tcp-connections`
* Integer
* Default: 20

Allow this many incoming TCP DNS connections simultaneously.

## `max-tcp-connections-per-client`
* Integer
* Default: 0

Maximum number of simultaneous TCP connections per client. 0 means unlimited.

## `max-tcp-transactions-per-conn`
* Integer
* Default: 0

Allow this many DNS queries in a single TCP transaction. 0 means unlimited.
Note that exchanges related to an AXFR or IXFR are not affected by this setting.

## `module-dir`
* Path

Directory for modules. Default depends on `PKGLIBDIR` during compile-time.

## `negquery-cache-ttl`
* Integer
* Default: 60

Seconds to store queries with no answer in the Query Cache. See
["Query Cache"](performance.md#query-cache).

## `no-config`
* Boolean
* Default: no

Do not attempt to read the configuration file.

## `no-shuffle`
* Boolean
* Default: no

Do not attempt to shuffle query results, used for regression testing.

## `overload-queue-length`
* Integer
* Default: 0 (disabled)

If this many packets are waiting for database attention, answer any new
questions strictly from the packet cache.

## `reuseport`
* Boolean
* Default: No

On Linux 3.9 and some BSD kernels the `SO_REUSEPORT` option allows each
receiver-thread to open a new socket on the same port which allows for much
higher performance on multi-core boxes. Setting this option will enable use of
`SO_REUSEPORT` when available and seamlessly fall back to a single socket when
it is not available. A side-effect is that you can start multiple servers on the
same IP/port combination which may or may not be a good idea. You could use this
to enable transparent restarts, but it may also mask configuration issues and
for this reason it is disabled by default.

## `security-poll-suffix`
* String
* Default: secpoll.powerdns.com.
* Available since: 3.4.1

Domain name from which to query security update notifications. Setting this to
an empty string disables secpoll.

## `server-id`
* String
* Default: The hostname of the server

This is the server ID that will be returned on an EDNS NSID query.

## `only-notify`
* IP Ranges, separated by commas or whitespace
* Default: 0.0.0.0/0, ::/0

For type=MASTER zones (or SLAVE zones with slave-renotify enabled) PowerDNS
automatically sends NOTIFYs to the name servers specified in the NS records.
By specifying networks/mask as whitelist, the targets can be limited. The default
is to notify the world. To completely disable these NOTIFYs set `only-notify` to an
empty value. Independent of this setting, the IP addresses or netmasks configured
with [`also-notify`](#also-notify) and `ALSO-NOTIFY` domain metadata always receive
AXFR NOTIFYs.

Note: Even if NOTIFYs are limited by a netmask, PowerDNS first has to resolve all the
hostnames to check their IP addresses against the specified whitelist. The resolving
may take considerable time, especially if those hostnames are slow to resolve. If you
do not need to NOTIFY the slaves defined in the NS records (e.g. you are using another
method to distribute the zone data to the slaves), then set `only-notify` to an empty
value and specify the notification targets explicitly using [`also-notify`](#also-notify)
and/or `ALSO-NOTIFY` domain metadata to avoid this potential bottleneck.

## `out-of-zone-additional-processing`
* Boolean
* Default: yes

Do out of zone additional processing. This means that if a malicious user adds a
'.com' zone to your server, it is not used for other domains and will not
contaminate answers. Do not enable this setting if you run a public DNS service
with untrusted users.

The docs had previously indicated that the default was "no", but the default has
been "yes" since 2005.

## `outgoing-axfr-expand-alias`
* Boolean
* Default: no

If this is enabled, ALIAS records are expanded (synthesised to their A/AAAA)
during outgoing AXFR. This means slaves will not automatically follow changes
in those A/AAAA records unless you AXFR regularly!

If this is disabled (the default), ALIAS records are sent verbatim during
outgoing AXFR. Note that if your slaves do not support ALIAS, they will return
NODATA for A/AAAA queries for such names.

## `prevent-self-notification`
* Boolean
* Default: yes
* Available since: 3.3

PowerDNS Authoritative Server attempts to not send out notifications to itself
in master mode. In very complicated situations we could guess wrong and not
notify a server that should be notified. In that case, set
prevent-self-notification to "no".

## `query-cache-ttl`
* Integer
* Default: 20

Seconds to store queries with an answer in the Query Cache. See
["Query Cache"](performance.md#query-cache).

## `query-local-address`
* IPv4 Address
* Default: 0.0.0.0

The IP address to use as a source address for sending queries. Useful if you
have multiple IPs and PowerDNS is not bound to the IP address your operating
system uses by default for outgoing packets.

## `query-local-address6`
* IPv6 Address
* Default: ::

Source IP address for sending IPv6 queries.

## `query-logging`
* Boolean
* Default: no

Boolean, hints to a backend that it should log a textual representation of
queries it performs. Can be set at runtime.

## `queue-limit`
* Integer
* Default: 1500

Maximum number of milliseconds to queue a query. See
["Authoritative Server Performance"](performance.md).

## `receiver-threads`
* Integer
* Default: 1

Number of receiver (listening) threads to start. See
["Authoritative Server Performance"](performance.md) for tuning details.

## `recursive-cache-ttl`
* Integer
* Default: 10
* Removed in: 4.1.0

Seconds to store recursive packets in the PacketCache. See
["Packet Cache"](performance.md#packet-cache).

## `recursor`
* IP Address
* Removed in: 4.1.0

If set, recursive queries will be handed to the recursor specified here. See
["Recursion"](recursion.md).

## `resolver`
* IP Addresses with optional port, separated by commas
* Added in: 4.1.0

Use these resolver addresses for ALIAS and the internal stub resolver.
If this is not set, `/etc/resolv.conf` is parsed for upstream resolvers.

## `retrieval-threads`
* Integer
* Default: 2

Number of AXFR slave threads to start.

## `setgid`
* String

If set, change group id to this gid for more security. See
["Security settings & considerations"](../common/security.md).

## `setuid`
* String

If set, change user id to this uid for more security. See
["Security settings & considerations](../common/security.md).

## `slave`
* Boolean
* Default: no

Turn on slave support. See ["Modes of operation"](modes-of-operation.md#slave-operation).

## `slave-cycle-interval`
* Integer
* 60

On a master, this is the amounts of seconds between the master checking the SOA
serials in its database to determine to send out NOTIFYs to the slaves. On slaves,
this is the number of seconds between the slave checking for updates to zones.

## `slave-renotify`
* Boolean
* Default: no

This setting will make PowerDNS renotify the slaves after an AXFR is *received*
from a master. This is useful when using when running a signing-slave.

## `signing-threads`
* Integer
* Default: 3

Tell PowerDNS how many threads to use for signing. It might help improve signing
speed by changing this number.

## `soa-expire-default`
* Integer
* Default: 604800

Default [SOA](../types.md#soa) expire.

## `soa-minimum-ttl`
* Integer
* Default: 3600

Default [SOA](../types.md#soa) minimum ttl.

## `soa-refresh-default`
* Integer
* Default: 10800

Default [SOA](../types.md#soa) refresh.

## `soa-retry-default`
* Integer
* Default: 3600

Default [SOA](../types.md#soa) retry.

## `socket-dir`
* Path

Where the controlsocket will live. The default depends on `LOCALSTATEDIR` during
compile-time (usually `/var/run` or `/run`). See
["Controlsocket"](running.md#controlsocket).

This path will also contain the pidfile for this instance of PowerDNS called
`pdns.pid` by default. See [`config-name`](#config-name) and
[Virtual Hosting](running.md#virtual-hosting) how this can differ.

## `tcp-control-address`
* IP Address

Address to bind to for TCP control.

## `tcp-control-port`
* Integer
* Default: 53000

Port to bind to for TCP control.

## `tcp-control-range`
* IP Ranges, separated by commas or whitespace

Limit TCP control to a specific client range.

## `tcp-control-secret`
* String

Password for TCP control.

## `tcp-fast-open`
* Integer
* Default: 0 (Disabled)
* Available since: 4.1

Enable TCP Fast Open support, if available, on the listening sockets. The numerical
value supplied is used as the queue size, 0 meaning disabled.

## `tcp-idle-timeout`
* Integer
* Default: 5

Maximum time in seconds that a TCP DNS connection is allowed to stay open
while being idle, meaning without PowerDNS receiving or sending even a single byte.

## `traceback-handler`
* Boolean
* Default: yes

Enable the Linux-only traceback handler.

## `trusted-notification-proxy`
* String

IP address of incoming notification proxy

## `udp-truncation-threshold`
* Integer
* Default: 1680

EDNS0 allows for large UDP response datagrams, which can potentially raise
performance. Large responses however also have downsides in terms of reflection
attacks. Up till PowerDNS Authoritative Server 3.3, the truncation limit was set
at 1680 bytes, regardless of EDNS0 buffer size indications from the client.
Beyond 3.3, this setting makes our truncation limit configurable. Maximum value
is 65535, but values above 4096 should probably not be attempted.

## `version-string`
* Any of: `anonymous`, `powerdns`, `full`, String
* Default: full

When queried for its version over DNS
(`dig chaos txt version.bind @pdns.ip.address`), PowerDNS normally responds
truthfully. With this setting you can overrule what will be returned. Set the
`version-string` to `full` to get the default behaviour, to `powerdns` to just
make it state `served by PowerDNS - http://www.powerdns.com`. The `anonymous`
setting will return a ServFail, much like Microsoft nameservers do. You can set
this response to a custom value as well.

## `webserver`
* Boolean
* Default: no

Start a webserver for monitoring. See
["Performance Monitoring"](../common/logging.md#performance-monitoring).
Before 4.1.0, it was necessary to enable the webserver to use the REST API,
this is no longer the case.

## `webserver-address`
* IP Address
* Default: 127.0.0.1

IP Address for webserver/API to listen on. See
["Performance Monitoring"](../common/logging.md#performance-monitoring).

## `webserver-allow-from`
* IP ranges, separated by commas or whitespace
* Default: 0.0.0.0/0,::/0

Webserver/API access is only allowed from these subnets.

## `webserver-password`
* String

The plaintext password required for accessing the webserver. See
["Performance Monitoring"](../common/logging.md#performance-monitoring).

## `webserver-port`
* Integer
* Default: 8001

The port where webserver/API will listen on. See ["Performance Monitoring"](../common/logging.md#performance-monitoring).

## `webserver-print-arguments`
* Boolean
* Default: no

If the webserver should print arguments. See ["Performance Monitoring"](../common/logging.md#performance-monitoring).

## `write-pid`
* Boolean
* Default: yes

If a PID file should be written. Available since 4.0.

## `xfr-max-received-mbytes`
* Integer
* Default: 100

Specifies the maximum number of received megabytes allowed on an incoming AXFR/IXFR update, to prevent
resource exhaustion. A value of 0 means no restriction.
