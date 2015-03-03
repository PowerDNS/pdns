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

## `allow-axfr-ips`
* IP ranges, separated by commas
* Default: 127.0.0.0/8,::1

If set, only these IP addresses or netmasks will be able to perform AXFR.

## `allow-dns-update-from`
* IP ranges, separated by commas

Allow DNS updates from these IP ranges.

## `allow-notify-from`
* IP ranges, separated by commas
* Default: 0.0.0.0/0,::/0
* Available since: 3.5.0

Allow AXFR NOTIFY from these IP ranges.
Setting this to an empty string will drop all incoming notifies.

## `allow-recursion`
* IP ranges, separated by commas
* Default: 0.0.0.0/0

By specifying `allow-recursion`, recursion can be restricted to netmasks
specified. The default is to allow recursion from everywhere. Example:
`allow-recursion=198.51.100.0/24, 10.0.0.0/8, 192.0.2.4`.

## `also-notify`
* IP adresses, separated by commas

When notifying a domain, also notify these nameservers. Example:
`also-notify=192.0.2.1, 203.0.113.167`. The IP adresses listed in `also-notify`
always receive a notification. Even if they do not match the list in
[`only-notify`](#also-notify).

## `any-to-tcp`
* Boolean
* Default: no
* Available since: 3.3

Answer questions for the ANY and RRSIG types on UDP with a truncated packet that
refers the remote server to TCP. Useful for mitigating reflection attacks.

## `cache-ttl`
* Integer
* Default: 20

Seconds to store packets in the PacketCache. See
["Packet Cache"](performance.md#packet-cache).

## `carbon-ourname`

* String
* Default: the hostname of the server
* Available since: 3.3.1

If sending carbon updates, if set, this will override our hostname. See
["PowerDNS Metrics"](../common/logging.md#sending-to-carbongraphitemetronome).

## `carbon-server`
* IP Address
* Available since: 3.3.1

Send all available metrics to this server via the carbon protocol, which is used
by graphite and metronome. See
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

## `config-dir`
* Path

Location of configuration directory (`pdns.conf`). Usually `/etc/powerdns`, but
this depends on `SYSCONFDIR` during compile-time.

## `config-name`
* String

Name of this virtual configuration - will rename the binary image. See
["Virtual hosting"](virtual.md).

## `control-console`
Debugging switch - don't use.

## `daemon`
* Boolean
* Default: no

Operate as a daemon.

## `default-ksk-algorithms`
* String
* Default: rsasha256

The algorithm that should be used for the KSK when running
[`pdnssec secure-zone`](internals.md#pdnssec).
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
[`pdnssec secure-zone`](internals.md#pdnssec).

## `default-soa-name`
* String
* Default: a.misconfigured.powerdns.server

Name to insert in the SOA record if none set in the backend.

## `default-soa-mail`
* String

Mail address to insert in the SOA record if none set in the backend.

## `default-ttl`
* Integer
* Default: 3600

TTL to use when none is provided.

## `default-zsk-algorithms`
* String
* Default: rsasha256

The algorithm that should be used for the ZSK when running
[`pdnssec secure-zone`](internals.md#pdnssec).
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
[`pdnssec secure-zone`](internals.md#pdnssec).

## `direct-dnskey`
* Boolean
* Default: no

Read additional ZSKs from the records table/your BIND zonefile. If not set,
DNSKEY recornds in the zonefiles are ignored.

## `disable-axfr`
* Boolean
* Default: no

Do not allow zone transfers.

## `disable-axfr-rectify`
* Boolean
* Default: no

Disable the rectify step during an outgoing AXFR. Only required for regression
testing.

## `disable-tcp`
* Boolean
* Default: no

Do not listen to TCP queries. Breaks RFC compliance.

## `distributor-threads`
* Integer
* Default: 3

Number of Distributor (backend) threads to start per receiver thread. See
["Authoritative Server Performance"](performance.md).

## `do-ipv6-additional-processing`
* Boolean
* Default: yes

Perform AAAA additional processing. This sends AAAA records in the ADDITIONAL
section when sending a referral.

## `edns-subnet-option-number`
* Integer
* Removed in 3.4.

If [`edns-subnet-processing`](#edns-subnet-processing) is enabled, this option
allows the user to override the option number.

## `edns-subnet-processing`
* Boolean
* Default: no

Enables EDNS subnet processing, for backends that support it.

## `entropy-source`
* Path
* Default: /dev/urandom

Entropy source file to use.

## `experimental-api-readonly`
* Boolean
* Default: no
* Available since: 3.4

Disallow data modification through the json API when set.

## `experimental-api-key`
* String
* Available since: 3.4.1

experimental-api-key REST API Static authentication key (required for API use)

## `experimental-dname-processing`
* Boolean
* Default: no

Synthesise CNAME records from DNAME records as required. This approximately
doubles query load. **Do not combine with DNSSEC!**

## `experimental-dnsupdate`
* Boolean
* Default: no

Enable/Disable DNS update (RFC2136) support.

## `forward-dnsupdates`
* Boolean
* Default: no

Forward DNS updates sent to a slave to the master.

## `guardian`
* Boolean
* Default: no

Run within a guardian process. See ["Guardian"](internals.md#guardian).

## `help`
Provide a helpful message

## `include-dir`
* Path

Directory to scan for additional config files. All files that end with .conf are
loaded in order using `POSIX` as locale.

## `launch`
* Backend names, separated by commas

Which backends to launch and order to query them in. See
["Modules & Backends"](internals.md#modules-backends).

## `lazy-recursion`
* Boolean
* Default: yes
* Removed in: 3.2

Check local data first before recursing. See ["Recursion"](recursion.md).

## `load-modules`
* Path

Load this module - supply absolute or relative path. See
["Modules & Backends"](internals.md#modules-backends).

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

Maximum number of cache entries. 1 million (the default) will generally suffice
for most installations.

## `max-ent-entries`
* Integer
* Default: 100000

Maximum number of empty non-terminals to add to a zone. This is a protection
measure to avoid database explosion due to long names.

## `max-nsec3-iterations`
* Integer
* Default: 500

Limit the number of NSEC3 hash iterations

## `max-queue-length`
* Integer
* Default: 5000

If this many packets are waiting for database attention, consider the situation
hopeless and respawn.

## `max-signature-cache-entries`
* Integer
* Default: 2^64 (on 64-bit systems)

Maximum number of signatures cache entries

## `max-tcp-connections`
* Integer
* Default: 10

Allow this many incoming TCP DNS connections simultaneously.

## `module-dir`
* Path

Directory for modules. See ["Modules and Backends"](internals.md#modules-backends).
Default depends on `PKGLIBDIR` during compile-time.

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

Domain name from which to query security update notifications

## `server-id`
* String
* Default: The hostname of the server

This is the server ID that will be returned on an EDNS NSID query.

## `only-notify`
* IP Ranges, separated by commas or whitespace
* Default: 0.0.0.0/0, ::/0

Only send AXFR NOTIFY to these IP addresses or netmasks. The default is to
notify the world. The IP addresses or netmasks in [`also-notify`](#also-notify)
or ALSO-NOTIFY metadata always receive AXFR NOTIFY.

## `out-of-zone-additional-processing`
* Boolean
* Default: no

Do out of zone additional processing. This means that if a malicious user adds a
'.com' zone to your server, it is not used for other domains and will not
contaminate answers. Do not enable this setting if you run a public DNS service
with untrusted users.

## `pipebackend-abi-version`
* Integer
* Default: 1

ABI version to use for the pipe backend. See
["PipeBackend protocol"](backend-pipe.md#pipebackend-protocol).

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

Seconds to store recursive packets in the PacketCache. See
["Packet Cache"](internals.md#packet-cache).

## `recursor`
* IP Address

If set, recursive queries will be handed to the recursor specified here. See
["Recursion"](recursion.md).

## `retrieval-threads`
* Integer
* Default: 2

Number of AXFR slave threads to start.

## `send-root-referral`
* Boolean or `lean`
* Default: no

if set, PowerDNS will send out old-fashioned root-referrals when queried for
domains for which it is not authoritative. Wastes some bandwidth but may solve
incoming query floods if domains are delegated to you for which you are not
authoritative, but which are queried by broken recursors. It is possible to
specify 'lean' root referrals, which waste less bandwidth.

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

Number of seconds to schedule slave up-to-date checks of domains whose status is
unknown.

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

## `soa-serial-offset`
* Integer
* Removed in: 3.4

If your database contains single-digit SOA serials and you need to host .DE
domains, this setting can help placate their 6-digit SOA serial requirements.
Suggested value is to set this to 1000000 which adds 1000000 to all SOA Serials
under that offset.

## `socket-dir`
* Path

Where the controlsocket will live. The default depends on `LOCALSTATEDIR` during
compile-time (usually `/var/run` or `/run`). See
["Controlsocket"](internals.md#controlsocket).

This path will also contain the pidfile for this instance of PowerDNS called
`pdns.pid` by default. See [`config-name`](#config-name) and
[Virtual Hosting](virtual.md) how this can differ.

## `strict-rfc-axfrs`
* Boolean
* Default: no

Perform strictly RFC-conforming AXFRs, which are slow, but may be necessary to
placate some old client tools.

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

## `webserver-address`
* IP Address
* Default: 127.0.0.1

IP Address of webserver to listen on. See
["Performance Monitoring"](../common/logging.md#performance-monitoring).

## `webserver-allow-from`
* IP ranges, separated by commas or whitespace

Webserver access is only allowed from these subnets

## `webserver-password`
* String

The plaintext password required for accessing the webserver. See
["Performance Monitoring"](../common/logging.md#performance-monitoring).

## `webserver-port`
* Integer
* Default: 8001

The port where webserver to listen on. See ["Performance Monitoring"](../common/logging.md#performance-monitoring).

## `webserver-print-arguments`
* Boolean
* Default: no

If the webserver should print arguments. See ["Performance Monitoring"](../common/logging.md#performance-monitoring).
