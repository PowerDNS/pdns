# Scripting The Recursor
In the PowerDNS recursor, it is possible to modify resolving behaviour using
simple scripts written in the [Lua](http://www.lua.org) programming language.
This page documents the Recursor 4.0.0 and beyond version of the scripting API.

**Note**: This describes the Lua scripts as supported by 4.x. They are very
different than the ones from 3.x, but tend to be faster and more correct.

These scripts can be used to quickly override dangerous domains, fix things
that are wrong, for load balancing or for legal or commercial purposes. The
scripts can also protect you or your users from malicious traffic.

Lua is extremely fast and lightweight, easily supporting hundreds of thousands
of queries per second. The Lua language is explained very well in the excellent
book [Programming in Lua](http://www.amazon.com/exec/obidos/ASIN/859037985X/lua-pilindex-20).
If you already have programming experience,
[Learn Lua in 15 Minutes](http://tylerneylon.com/a/learn-lua/) is a great primer.

For extra performance, a Just In Time compiled version of Lua called
[LuaJIT](http://luajit.org/) is supported.

Queries can be intercepted in many places:

* before any packet parsing begins (`ipfilter`)
* before the resolving logic starts to work (`preresolve`)
* after the resolving process failed to find a correct answer for a domain (`nodata`, `nxdomain`)
* after the whole process is done and an answer is ready for the client (`postresolve`)
* before an outgoing query is made to an authoritative server (`preoutquery`)

## Configuring Lua scripts
In order to load scripts, the PowerDNS Recursor must have Lua support built
in.  The packages distributed from the PowerDNS website have this language
enabled, other distributions may differ. By default, the Recursor's configure
script will attempt to detect if Lua is available.

**note**: Only one script can be loaded at the same time. If you load a different
script, the current one will be replaced (safely)!

If Lua support is available, a script can be configured either via the
configuration file, or at runtime via the `rec_control` tool.  Scripts can
be reloaded or unloaded at runtime with no interruption in operations.  If a
new script contains syntax errors, the old script remains in force.

On the command line, or in the configuration file, the setting
[`lua-dns-script`](settings.md#lua-dns-script) can be used to supply a full path
to the Lua script.

At runtime, `rec_control reload-lua-script` can be used to either reload the
script from its current location, or, when passed a new file name, load one
from a new location.  A failure to parse the new script will leave the old
script in working order.

**Note**: It is also possible to precompile scripts using `luac`, and have
PowerDNS load the result.  This means that switching scripts is faster, and
also that you'll be informed about syntax errors at compile time.

Finally, `rec_control unload-lua-script` can be used to remove the currently
installed script, and revert to unmodified behaviour.

# Writing Lua PowerDNS Recursor scripts
To get a quick start, we have supplied a sample script that showcases all functionality described below. Please
find it [here](https://github.com/PowerDNS/pdns/blob/master/pdns/powerdns-example-script.lua). 

Addresses and DNS Names are not passed as strings but as native objects. This
allows for easy checking against [netmasks](#netmask-groups) and [domain sets]().
It also means that to print such names, the `:toString` method must be used
(or even `:toStringWithPort` for addresses).

Comparing IP addresses and DNSNames is not done with '==' but with the `:equal` method. 

Once a script is loaded, PowerDNS looks for several functions, as detailed below.
All of these functions are optional.

## The DNSQuestion (`dq`) object
Apart from the `ipfilter`-function, all functions work on a `dq` (DNSQuestion)
object. This object contains details about the current state of the question.
This state can be modified from the various hooks. If a function returns 'true',
it will indicate that it handled a query. If it returns false, the Recursor will
continue processing unchanged (with one minor exception).

The DNSQuestion object contains at least the following fields:

* qname - DNS native version of the name this query is for
* qtype - type this query is for, can be compared against pdns.A, pdns.AAAA etc
* rcode - current DNS Result Code, which can be overridden, including to several magical values
* isTcp - whether the query have been received over TCP or UDP
* remoteaddr - address of the requestor
* localaddr - address this query was received on
* variable - a boolean which, if set, indicates the recursor should not packet cache this answer. Honored even when returning 'false'! Important when providing answers that vary over time or based on sender details.
* followupFunction - a string that signals the nameserver to take one of the following additional actions:
  * followCNAMERecords: When adding a CNAME to the answer, this tells the recursor to follow that CNAME. See [CNAME chain resolution](#cname-chain-resolution)
  * getFakeAAAARecords: Get a fake AAAA record, see [DNS64](#dns64)
  * getFakePTRRecords: Get a fake PTR record, see [DNS64](#dns64)
  * udpQueryResponse: Do a UDP query and call a handler, see [`udpQueryResponse`](#udpqueryresponse)

It also supports the following methods:

* `addAnswer(type, content, [ttl, name])`: add an answer to the record of `type` with `content`. Optionally supply TTL and the name of
  the answer too, which defaults to the name of the question
* `getRecords()`: get a table of DNS Records in this DNS Question (or answer by now)
* `setRecords(records)`: after your edits, update the answers of this question
* `getEDNSOption(num)`: get the EDNS Option with number `num`
* `getEDNSOptions()`: get a map of all EDNS Options
* `getEDNSSubnet()`: returns the netmask specified in the EDNSSubnet option, or empty if there was none

## `function ipfilter ( remoteip, localip, dh )`
This hook gets queried immediately after consulting the packet cache, but before
parsing the DNS packet. If this hook returns something else than false, the packet is dropped. 
However, because this check is after the packet cache, the IP address might still receive answers
that require no packet parsing. 

With this hook, undesired traffic can be dropped rapidly before using precious CPU cycles
for parsing.

`remoteip` is the IP(v6) address of the requestor, `localip` is the address on which the query arrived.
`dh` is the DNS Header of the query, and it offers the following methods:

* `getRD()`, `getAA()`, `getAD()`, `getCD()`, `getRD()`, `getRD()`, `getTC()`: query these bits from the DNS Header
* `getRCODE()`: get the RCODE of the query
* `getOPCODE()`: get the OPCODE of the query
* `getID()`: get the ID of the query

As an example, to filter all queries coming from 1.2.3.0/24, or with the AD bit set:

```
badips = newNMG()
badips:addMask("1.2.3.0/24")

function ipfilter(rem, loc, dh)
	return badips:match(rem) or dh:getAD()
end
```

This hook does not get the full DNSQuestion object, since filling out the fields
would require packet parsing, which is what we are trying to prevent with `ipfilter`.

### `function gettag(remote, ednssubnet, local, qname, qtype)`
The `gettag` function is invoked when `dq.tag` is called on a dq object or when
the Recursor attempts to discover in which packetcache an answer is available.
This function must return an integer, which is the tag number of the packetcache.
In addition to this integer, this function can return a table of policy tags.

The tagged packetcache can e.g. be used to answer queries from cache that have
e.g. been filtered for certain IPs (this logic should be implemented in the
`gettag` function). This ensure that queries are answered quickly compared to
setting dq.variable to `true`. In the latter case, repeated queries will pass
through the entire Lua script.

### `function preresolve(dq)`
is called before any DNS resolution is attempted, and if this function
indicates it, it can supply a direct answer to the DNS query, overriding the
internet.  This is useful to combat botnets, or to disable domains
unacceptable to an organization for whatever reason.

The rcode can be set to pdns.DROP to drop the query. Other statuses are normal DNS
return codes, like no error, NXDOMDAIN etc.

### `function postresolve(dq)`
is called right before returning a response to a client (and, unless
`variable` is set, to the packet cache too).  It allows inspection
and modification of almost any detail in the return packet.

### `function nxdomain(dq)`
is called after the DNS resolution process has run its course, but ended in
an 'NXDOMAIN' situation, indicating that the domain or the specific record
does not exist.  Works entirely like postresolve, but saves a trip through Lua for
answers which are not NXDOMAIN.

### `function nodata(dq)`
is just like `nxdomain`, except it gets called when a domain exists, but the
requested type does not.  This is where one would implement DNS64.

### `function preoutquery(dq)`
This hook is not called in response to a client packet, but fires when the Recursor
wants to talk to an authoritative server. When this hook sets the special result code -3,
the whole DNS client query causing this outquery gets dropped.

However, this function can also return records like the preresolve query above.

## Semantics
The functions must return `true` if they have taken over the query and wish that
the nameserver should not proceed with its regular query-processing. When a
function returns `false`, the nameserver will process the query normally until
a new function is called.

If a function has taken over a request, it should set an rcode (usually 0),
and specify a table with records to be put in the answer section of a
packet.  An interesting rcode is NXDOMAIN (3, or `pdns.NXDOMAIN`), which
specifies the non-existence of a domain.

The `ipfilter` and `preoutquery` hooks are different, in that `ipfilter` can
only return a true of false value, and that `preoutquery` can also set rcode -3
to signify that the whole query should be terminated.

A minimal sample script:

```
function nxdomain(dq)
	print("Intercepting NXDOMAIN for: ",dq.qname:toString())
	if dq.qtype == pdns.A
	then
		dq.rcode=0 -- make it a normal answer
		dq:addAnswer(pdns.A, "192.168.1.1")
		return true
	end
	return false
end
```

**Warning**: Please do NOT use the above sample script in production!
Responsible NXDomain redirection requires more attention to detail.

Useful 'rcodes' include 0 for "no error", `pdns.NXDOMAIN` for
"NXDOMAIN", `pdns.DROP` to drop the question from further processing (since
3.6, and such a drop is accounted in the 'policy-drops' metric).

## Helpful functions

### Netmask Groups
IP addresses are passed to Lua in native format. They can be matched against netmasks objects like this:
```
nmg = newNMG()
nmg:addMask("127.0.0.0/8")
nmg:addMasks({"213.244.168.0/24", "130.161.0.0/16"})
nmg:addMasks(dofile("bad.ips")) -- contains return {"ip1","ip2"..}

if nmg:match(dq.remote) then
	print("Intercepting query from ", dq.remote)
end
```

### IP Addresses
We move IP addresses around in native format, called ComboAddress within PowerDNS.
ComboAddresses can be IPv4 or IPv6, and unless you want to know, you don't need
to. You can make a ComboAddress with: `newCA("::1")`, and you can compare
it against a NetmaskGroup as described above.

To compare the address (so not the port) of two ComboAddresses, use `:equal`.

To convert an address to human-friendly representation, use `:toString()` or
`:toStringWithPort()`. To get only the port number, use `:getPort()`.

Other functions that can be called on a ComboAddress are:
 * `isIpv4` - true if the address is an IPv4 address
 * `isIpv6` - true if the address is an IPv6 address
 * `getBits` - the number of bits in the address

### DNSName
DNSNames are passed to various functions, and they sport the following methods:

* `:equal`: use this to compare two DNSNames in DNS native fashion. So 'PoWeRdNs.COM' matches 'powerdns.com'
* `:isPartOf`: returns true if a is a part of b. So: `newDN("www.powerdns.com"):isPartOf(newDN("CoM."))` returns true

To make your own DNSName, use `newDN("domain.name")`.

### DNS Suffix Match groups
The `newDS` function creates a "Suffix Match group" that allows fast checking if
a DNSName is part of a group. Add domains to this group with the `:add(domain)`
function of the object: `myDS:add("example.net")`, or with a list:
`myDS:add({"example.net", "example.com"}).

To check e.g. the dq.qname against this list, use `:check(dq.qname)`. This will
be `true` if dq.qname is part of any of the Suffix Match group domains.

This could e.g. be used to answer questions for known malware domains.

### Metrics
You can custom metrics which will be shown in the output of 'rec_control get-all'
and sent to the metrics server over the Carbon protocol, and also appear in the
JSON HTTP API.

Create a custom metric with: `myMetric= getMetric("name")`. This metric sports
the following metrics:

* `:inc()`: increase metric by 1
* `:incBy(amount)`: increase metric by amount
* `:set(to)`: set metric to value to
* `:get()`: get value of metric

Metrics are shared across all of PowerDNS and are fully atomic and high
performance. The myMetric object is effectively a pointer to an atomic value.

Note that metrics live in the same namespace as 'system' metrics. So if you
generate one that overlaps with a PowerDNS stock metric, you will get double
output and weird results.

### Logging
To log messages with the main PowerDNS Recursor process, use `pdnslog(message)`.
pdnslog can also write out to a syslog loglevel if specified.
Use `pdnslog(message, pdns.loglevels.LEVEL)` with the correct pdns.loglevels
entry.  Entries are listed in the following table:

* All - `pdns.loglevels.All`
* Alert - `pdns.loglevels.Alert`
* Critical - `pdns.loglevels.Critical`
* Error - `pdns.loglevels.Error`
* Warning - `pdns.loglevels.Warning`
* Notice - `pdns.loglevels.Notice`
* Info - `pdns.loglevels.Info`
* Debug - `pdns.loglevels.Debug`
* None - `pdns.loglevels.None`

`pdnslog(message)` will write out to Info by default.

`getregisteredname('www.powerdns.com')` returns `powerdns.com.`, based on Mozilla's
Public Suffix List. In general it will tell you the 'registered domain' for a given
name.

## DNS64
The `getFakeAAAARecords` and `getFakePTRRecords` followupFunctions can be used
to implement DNS64. See [DNS64 support in the PowerDNS Recursor](dns64.md) for
more information.

To get fake AAAA records for DNS64 usage, set dq.followupFunction to `getFakeAAAARecords`,
dq.followupPrefix to e.g. "64:ff9b::" and dq.followupName to the name you want to
synthesize an IPv6 address for.

For fake reverse (PTR) records, set dq.followupFunction to `getFakePTRRecords`
and set dq.followupName to the name to look up and dq.followupPrefix to the
same prefix as used with `getFakeAAAARecords`.

## CNAME chain resolution
It may be useful to return a CNAME record for Lua, and then have the
PowerDNS Recursor continue resolving that CNAME.  This can be achieved by
setting dq.followupFunction to `followCNAMERecords` and dq.followupDomain to
"www.powerdns.com". PowerDNS will do the rest.

## `udpQueryResponse`
The `udpQueryResponse` dq.followupFunction allows you to query a simple key-value
store over UDP asynchronously.

Several dq variables can be set:

* `udpQueryDest`: destination IP address to send the UDP packet to
* `udpQuery`: The content of the UDP payload
* `udpCallback`: The name of the callback function that is called when an answer is received

The callback function must accept the `dq` object and can find the response to
the UDP query in `dq.udpAnswer`.

In this callback function, `dq.followupFunction` can be set again to any of the
available functions for further processing.

This example script queries a simple key/value store over UDP to decide on whether
or not to filter a query:

```
!!include=../pdns/kv-example-script.lua
```

## Example Script

```
!!include=../pdns/powerdns-example-script.lua
```

### Dropping all traffic from botnet-infected users
Frequently, DoS attacks are performed where specific IP addresses are attacked, 
often by queries coming in from open resolvers. These queries then lead to a lot of 
queries to 'authoritative servers' which actually often aren't nameservers at all, but
just targets of attack.

The following script will add a requestor's IP address to a blocking set if they've
sent a query that caused PowerDNS to attempt to talk to a certain subnet.

This specific script is, as of January 2015, useful to prevent traffic to ezdns.it related
traffic from creating CPU load. This script requires PowerDNS Recursor 3.7 or later.

```
lethalgroup=newNMG()
lethalgroup:addMask("192.121.121.0/24") -- touch these nameservers and you die

function preoutquery(dq)
--	print("pdns wants to ask "..remoteip:tostring().." about "..domain.." "..qtype.." on behalf of requestor "..getlocaladdress())
	if(lethalgroup:match(dq.remoteaddr))
	then
--		print("We matched the group "..lethalgroup:tostring().."!", "killing query dead & adding requestor "..getlocaladdress().." to block list")
		dq.rcode = -3 -- "kill"	
		return true
	end
	return false
end
```
