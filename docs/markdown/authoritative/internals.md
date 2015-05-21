# PowerDNS Internals
PowerDNS is normally launched by the init.d script but is actually a binary called `pdns_server`. This file is started by the **start** and **monitor** commands to the init.d script. Other commands are implemented using the controlsocket.

# Controlsocket
The controlsocket is the means to contact a running PDNS daemon, or as we now know, a running `pdns_server`. Over this sockets, instructions can be sent using the `pdns_control` program. Like the `pdns_server`, this program is normally accessed via the init.d script.

# `pdns_control`
To communicate with PowerDNS Authoritative Server over the controlsocket, the `pdns_control` command is used. The init.d script also calls pdns\_control. The syntax is simple: `pdns_control command arguments`. Currently this is most useful for telling backends to rediscover domains or to force the transmission of notifications. See [Master](../authoritative/modes-of-operation.md#master).

Besides the commands implemented by the init.d script, for which see [Running The Authoritative Server](../authoritative/installation.md), the following `pdns_control` commands are available:

## `ccounts`
Returns counts on the contents of the cache.

## `current-config`
Retrieves the current configuration settings from the Authoritative Server instance. This can be useful to generate a from a running instance.

The output has the same format as `pdns_server --config`. You'll notice that all the are uncommented. This is because PowerDNS simply has values, and the default isn't known at runtime.

## `cycle`
Restart a PowerDNS instance. Only available when running in guardian mode.

## `notify DOMAIN`
Adds a domain to the notification list, causing PowerDNS to send out notifications to the nameservers of a domain. Can be used if a slave missed previous notifications or is generally hard of hearing. Use * to send notifications for all (type=MASTER) zones to all slaves.

## `notify-host DOMAIN HOST`
Same as above but with operator specified IP address as destination, to be used if you know better than PowerDNS.

## `ping`
'PING' the powerdns-guardian. Will return 'PONG' when it is available. (Only works when you are running in guardian mode)

## `purge`
Purges the entire Packet Cache - see [Authoritative Server Performance](../authoritative/performance.md).

## `purge RECORD`
Purges all entries for this exact record name - see [Authoritative Server Performance](../authoritative/performance.md).

## `purge RECORD`
Purges all cache entries ending on this name, effectively purging an entire domain - see [Authoritative Server Performance](../authoritative/performance.md).

## `purge`
Purges the entire Packet Cache - see [Authoritative Server Performance](../authoritative/performance.md).

## `rping`
'PING' the powerdns-instance. Will return 'PONG' when it is available.

## `rediscover`
Instructs backends that new domains may have appeared in the database, or, in the case of the Bind backend, in named.conf.

## `reload`
Instructs backends that the contents of domains may have changed. Many backends ignore this, the Bind backend will check timestamps for all zones (once queries come in for it) and reload if needed.

## `retrieve DOMAIN`
Retrieve a slave domain from its master. Done nearly immediately.

## `set VARIABLE VALUE`
Set a configuration parameter. Currently only the 'query-logging' parameter can be set.

## `token-login MODULE SLOT PIN`
Logs on to a PKCS#11 slot. You only need to login once per slot, even if you have multiple keys on single slot.

## `uptime`
Reports the uptime of the daemon in human readable form.

## `show VARIABLE`
Show a specific statistic. Use * for all. (You may need to quote as '*' or \\*).

## `version`
Returns the version of a running pdns daemon.

## `status`
Retrieves the status of PowerDNS. Only available when running with guardian.

# Guardian
When launched by the init.d script, `pdns_server` wraps itself inside a 'guardian'. This guardian monitors the performance of the inner `pdns_server` instance which shows up in the process list of your OS as `pdns_server-instance`. It is also this guardian that `pdns_control` talks to. A **STOP** is interpreted by the guardian, which causes the guardian to sever the connection to the inner process and terminate it, after which it terminates itself. The init.d script **DUMP** and **SHOW** commands need to access the inner process, because the guardian itself does not run a nameserver. For this purpose, the guardian passes controlsocket requests to the control console of the inner process. This is the same console as seen with init.d **MONITOR**.

# Modules & Backends
PowerDNS Authoritative Server has the concept of backends and modules. Non-static PowerDNS distributions have the ability to load new modules at runtime, while the static versions come with a number of modules built in, but cannot load more.

## Related Parameters
### `--help`
Outputs all known parameters, including those of launched backends, see below.

### `--launch=backend,backend1,backend1:name`
Launches backends. In its most simple form, supply all backends that need to be launched. If you find that you need to launch single backends multiple times, you can specify a name for later instantiations. In this case, there are 2 instances of backend1, and the second one is called 'name'. This means that `--backend1-setting` is available to configure the first or main instance, and `--backend1-name-setting` for the second one.

### `--load-modules=/directory/libyourbackend.so`
If backends are available in nonstandard directories, specify their location here. Multiple files can be loaded if separated by commas. Only available in non-static distributions.

### `--list-modules`
Will list all available modules, both compiled in and in dynamically loadable modules.

To run on the command line, use the `pdns_server` binary. For example, to see options for the gpgsql backend, use the following:

```
      $ /usr/sbin/pdns_server --launch=gpgsql --help=gpgsql
```

# How PowerDNS translates DNS queries into backend queries
A DNS query is not a straightforward lookup. Many DNS queries need to check the backend for additional data, for example to determine if an unfound record should lead to an NXDOMAIN ('we know about this domain, but that record does not exist') or an unauthoritative response.

Simplified, without CNAME processing, wildcards, referrals and DNSSEC, the algorithm is like this:

When a query for a `qname`/`qtype` tuple comes in, PowerDNS queries backends to find the closest matching SOA, thus figuring out what backend owns this zone. When the right backend has been found, PowerDNS issues a `qname`/`ANY` query to the backend. If the response is empty, NXDOMAIN is concluded. If the response is not empty, any contents matching the original qtype are added to the list of records to return, and NOERROR is set.

Each of these records is now investigated to see if it needs 'additional processing'. This holds for example for MX records which may point to hosts for which the PowerDNS backends also contain data. This involves further lookups for A or AAAA records.

After all additional processing has been performed, PowerDNS sieves out all double records which may well have appeared. The resulting set of records is added to the answer packet, and sent out.

A zone transfer works by looking up the `domain_id` of the SOA record of the name and then listing all records of that `domain_id`. This is why all records in a domain need to have the same domain\_id.

If no SOA was found, an unauthoritative no-error is returned.

PowerDNS (before 3.0) broke strict RFC compatibility by not always checking for the presence of a SOA record first. This was unlikely to lead to problems though.

# Adding new DNS record types
Here are the full descriptions on how we added the TLSA record type to all PowerDNS products, with links to the actual source code.

First, define the TLSARecordContent class in [dnsrecords.hh](http://wiki.powerdns.com/trac/browser/trunk/pdns/pdns/dnsrecords.hh?rev=2338#L307):

```
class TLSARecordContent : public DNSRecordContent
{
public:
  includeboilerplate(TLSA) 
  uint8_t d_certusage, d_selector, d_matchtype;
  string d_cert;
};
```

The 'includeboilerplate(TLSA)' generates the four methods that do everything PowerDNS would ever want to do with a record:
-   read TLSA records from zonefile format
-   write out a TLSA record in zonefile format
-   read a TLSA record from a packet
-   write a TLSA record to a packet

The [actual parsing code](http://wiki.powerdns.com/trac/browser/trunk/pdns/pdns/dnsrecords.cc?rev=2638#L226):

```
boilerplate_conv(TLSA, 52,
                 conv.xfr8BitInt(d_certusage);
                 conv.xfr8BitInt(d_selector);
                 conv.xfr8BitInt(d_matchtype);
                 conv.xfrHexBlob(d_cert, true);
                 )
```

This code defines the TLSA rrtype number as 52. Secondly, it says there are 3 eight bit fields for Certificate Usage, Selector and Match type. Next, it defines that the rest of the record is the actual certificate (hash). ['conv'](http://wiki.powerdns.com/trac/browser/trunk/pdns/pdns/dnsparser.hh?rev=2338#L70) methods are supplied for all DNS data types in use.

Now add TLSRecordContent::report() to [reportOtherTypes()](http://wiki.powerdns.com/trac/browser/trunk/pdns/pdns/dnsrecords.cc?rev=2338#L364).

And that's it. For completeness, add TLSA and 52 to the QType enum in qtype.hh, which makes it easier to refer to the TLSA record in code if so required.
