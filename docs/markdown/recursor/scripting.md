# Scripting The Recursor
As of version 3.1.7 of the PowerDNS Recursor, it is possible to modify
resolving behaviour using simple scripts written in the
[Lua](http://www.lua.org) programming language.

These scripts can be used to quickly override dangerous domains, fix things
that are wrong, for load balancing or for legal or commercial purposes.

Lua is extremely fast and lightweight, easily supporting hundreds of
thousands of queries per second. The Lua language is explained very
well in the excellent book [Programming in Lua](http://www.amazon.com/exec/obidos/ASIN/859037985X/lua-pilindex-20).

Queries can be intercepted in many places: 

* before any packet parsing begins (`ipfilter`, since 3.7)
* before the resolving logic starts to work (`preresolve`)
* after the resolving process failed to find a correct answer for a domain (`nodata`, `nxdomain`)
* after the whole process is done and an answer is ready for the client (`postresolve`)
* before an outgoing query is made to an authoritative server (`preoutquery`, since 3.7)

## Configuring Lua scripts

In order to load scripts, the PowerDNS Recursor must have Lua support built
in.  The packages distributed from the PowerDNS website have this language
enabled, other distributions may differ.  To compile with Lua support, use:
`LUA=1 make` or `LUA=1 gmake` as the case may be.  Paths to the Lua include
files and binaries may be found near the top of the `Makefile`, or passed 
to `configure`.

**note**: Only one script can be loaded at the same time. If you load a different
script, the current one will be replaced!

If Lua support is available, a script can be configured either via the
configuration file, or at runtime via the `rec_control` tool.  Scripts can
be reloaded or unloaded at runtime with no interruption in operations.  If a
new script contains syntax errors, the old script remains in force.

On the command line, or in the configuration file, the setting
`lua-dns-script` can be used to supply a full path to a 'lua' script.

At runtime, `rec_control reload-lua-script` can be used to either reload the
script from its current location, or, when passed a new file name, load one
from a new location.  A failure to parse the new script will leave the old
script in working order.

**Note**: It is also possible to precompile scripts using `luac`, and have
PowerDNS load the result.  This means that switching scripts is faster, and
also that you'll be informed about syntax errors at compile time.

Finally, `rec_control unload-lua-script` can be used to remove the currently
installed script, and revert to unmodified behaviour.

## Writing Lua PowerDNS Recursor scripts
Once a script is loaded, PowerDNS looks for several functions, as detailed below. All of these functions are optional.

### `function ipfilter ( remoteip )`
This hook gets queried immediately after consulting the packet cache, but before
parsing the DNS packet. If this hook returns something else than -1, the packet is dropped. 
However, because this check is after the packet cache, the IP address might still receive answers
that require no packet parsing. 

With this hook, undesired traffic can be dropped rapidly before using precious CPU cycles
for parsing.

Available since 3.7.

**Note**: `remoteip` is passed as an `iputils.ca` type (for which see below).

### `preresolve ( remoteip, domain, qtype )`
is called before any DNS resolution is attempted, and if this function indicates it, it can supply a direct answer to the DNS query, overriding the internet. This is useful to combat botnets, or to disable domains unacceptable to an organization for whatever reason.

### `postresolve ( remoteip, domain, qtype, records, origrcode )`
is called right before returning a response to a client (and, unless `setvariable()` is called, to the packet cache too). It allows inspection and modification of almost any detail in the return packet. Available since version 3.4.

### `function nxdomain ( remoteip, domain, qtype )`
is called after the DNS resolution process has run its course, but ended in an 'NXDOMAIN' situation, indicating that the domain or the specific record does not exist. This can be used for various purposes.

### `function nodata ( remoteip, domain, qtype, records )`
is just like `nxdomain`, except it gets called when a domain exists, but the requested type does not. This is where one would implement DNS64. Available since version 3.4.

### `function preoutquery ( remoteip, domain, qtype )`
This hook is not called in response to a client packet, but fires when the Recursor
wants to talk to an authoritative server. When this hook returns the special result code -3,
the whole DNS client query causing this outquery gets dropped.

However, this function can also return records like the preresolve query above.

Within `preoutquery`, `getlocaladdress()` returns the IP address of the original client requestor.

Available since 3.7.

**Note**: `remoteip` is passed as an `iputils.ca` type (for which see below).

## Semantics

All these functions are passed the IP address of the requester. Most also get passed the name and type being requested. In return, these functions indicate if they have taken over the request, or want to let normal proceedings take their course.

If a function has taken over a request, it should return an rcode (usually 0), and specify a table with records to be put in the answer section of a packet. An interesting rcode is NXDOMAIN (3, or `pdns.NXDOMAIN`), which specifies the non-existence of a domain. Returning -1 and an empty table signifies that the function chose not to intervene.

The `ipfilter` and `preoutquery` hooks are different, in that `ipfilter` can only return a true of false value, and
that `preoutquery` can also return -3 to signify that the whole query should be terminated.

A minimal sample script:

```
function nxdomain ( ip, domain, qtype )
  print ("nxhandler called for: ", ip, domain, qtype)

  ret={}
  if qtype ~= pdns.A then return pdns.PASS, ret end  --  only A records
  if not string.find(domain, "^www%.") then return pdns.PASS, ret end  -- only things that start with www.
  if not matchnetmask(ip, "10.0.0.0/8", "192.168.0.0/16")  then return pdns.PASS, ret end -- only interfere with local queries
  ret[1]={qtype=pdns.A, content="192.0.2.13"}    -- add IN A 192.0.2.13
  ret[2]={qtype=pdns.A, content="192.0.2.21"}    -- add IN A 192.0.2.21
  setvariable()
  return 0, ret                 -- return no error, plus records
end
```

**Warning**: Please do NOT use the above sample script in production!
Responsible NXDomain redirection requires more attention to detail.

Note that the domain is passed to the Lua function terminated by a '.'. A
more complete sample script is provided as `powerdns-example-script.lua` in
the PowerDNS Recursor distribution.

The answer content format is (nearly) identical to the storage in the
PowerDNS Authoritative Server database, or as in zone files.  The exception
is that, unlike in the database, there is no 'prio' field, which means that
an MX record with priority 25 pointing to 'smtp.example.net' would be
encoded as '25 smtp.example.net.'.

Useful return 'rcodes' include 0 for "no error", `pdns.NXDOMAIN` for
"NXDOMAIN", `pdns.DROP` to drop the question from further processing (since
3.6, and such a drop is accounted in the 'policy-drops' metric).

Fields that can be set in the return table include:

* content: Content of the record, as specified above in 'zone file format'. No default, mandatory field.
* place: Place of this record. Defaults to 1, indicating 'Answer' section. Can also be 2, for Authority of 3 for Additional. When using this rare feature, always emit records with 'Place' in ascending order. This field is usually not needed.
* qname: qname of the answer, the 'name' of the record. Defaults to the name of the query, which is almost always correct except when specifying additional records or rolling out a CNAME chain.
* qtype: Currently the numerical qtype of the answer, defaulting to '1' which is an A record. Can be also be specified as `pdns.A`, or `pdns.CNAME` etc.
* ttl: Time to live of a record. Defaults to 3600. Be sure not to specify differing TTLs within answers with an identical qname. While this will be encoded in DNS, actual results may be undesired.
* qclass: Query-Class of a record. Defaults to 1 (IN). Be sure to always return the correct qclass in each record! Valid query-classes are 1 (IN), 3 (CHAOS), 254 (NONE) and 255 (ANY).

**Warning**: Only the IN class (1) is fully supported!

**Warning**: The result table must have indexes that start at 1! Otherwise
the first or confusingly the last entry of the table will be ignored.  A
useful technique is to return data using: `return 0, {{qtype=1,
content="192.0.2.4"}, {qtype=1, content="4.3.2.1"}}` as this will get the
numbering right automatically.

## Helpful functions

The function `matchnetmask(ip, netmask1, netmask2..)` (or `matchnetmask(ip,
{netmask1, netmask2})`) is available to match incoming queries against a
number of netmasks.  If any of these match, the function returns true.

To log messages with the main PowerDNS Recursor process, use
`pdnslog(message)`.  Available since version 3.2.  pdnslog can also write
out to a syslog loglevel if specified.  Use `pdnslog(message,
pdns.loglevels.LEVEL)` with the correct pdns.loglevels entry.  Entries are
listed in the following table:

|&nbsp;|&nbsp;|
|:--||:--|
|All|pdns.loglevels.All|
|Alert|pdns.loglevels.Alert|
|Critical|pdns.loglevels.Critical|
|Error|pdns.loglevels.Error|
|Warning|pdns.loglevels.Warning|
|Notice|pdns.loglevels.Notice|
|Info|pdns.loglevels.Info|
|Debug|pdns.loglevels.Debug|
|None|pdns.loglevels.None|

`pdnslog(message)` will write out to Info by default.

To retrieve the IP address on which a query was received, use `getlocaladdress()`. Available since version 3.2.
In `preoutquery`, `getlocaladdress()` returns the address of the client that caused the outgoing query.

To indicate that an answer should not be cached in the packet cache, use
`setvariable()`.  Available since version 3.3.

`getregisteredname('www.powerdns.com')` returns `powerdns.com.`, based on Mozilla's
Public Suffix List. In general it will tell you the 'registered domain' for a given
name.

To get fake AAAA records for DNS64 usage, use `return "getFakeAAAARecords",
domain, "fe80::21b:77ff:0:0"`.  Available since version 3.4.

## IP Address and netmask processing
(Available in PowerDNS Recursor versions released after 3.6.2)

To prevent the conversion of IP addresses to strings and to aid in the rapid
filtering of queries based on IP addresses, PowerDNS provides an 'iputils'
module to any scripts it hosts.

The iputils module can create four kinds of objects: `ca`, `ipset`,
`netmask` and `netmaskgroup`.  IP addresses are represented by `ca`, which
is a wrapper around the internal PowerDNS ComboAddress class.  

An `ipset` is a rapidly searchable container of `ca` addresses, suitable for 
very large sets and high query rates.

A `netmask` is an IPv4 of IPv6 netmask, to which we can match `ca`
instances.  Finally, the `netmaskgroup` is a set of `netmask`s to which a
`ca` can be matched. The `netmaskgroup` is a lot slower, but more powerful,
than the `ipset`, which can only do exact matches.

This is perhaps all explained best as a little sample script:

```
ca=iputils.newca("127.0.0.1")
ca2=iputils.newca("127.0.0.1")
ca3=iputils.newca("::1")
ca4=iputils.newca("130.161.180.1:53")
ca5=iputils.newca("[::1]:53")

print("ca", ca)
print("ca2", ca2:tostring())
print("ca4", ca4:tostringwithport())
print("ca5", ca5:tostringwithport())

print("ca==ca2",ca==ca2)
print("ca==ca3",ca==ca3)

ipset=iputils.newipset()

for _,a in pairs({ca, ca3, ca5})
do
	print("Adding ",a," to the set")
	ipset[a]=1
end

print("Is ",ca," in our set: ", ipset[ca])
print("Is ",ca2," in our set: ", ipset[ca2])
print("Is ",ca4," in our set: ", ipset[ca4])

netmask=iputils.newnm("10.0.0.0/8")
print("Our netmask: ",netmask)
print("Does it match ", ca4, netmask:match(ca4))
ca5=iputils.newca("10.1.2.3")
print("Does it match ", ca5, netmask:match(ca5))

nmgroup=iputils.newnmgroup()
nmgroup:add("192.168.0.0/16")
nmgroup:add("10.0.0.0/8")
nmgroup:add("fe80::/16")

print("Our netmask group: ",nmgroup)
print("Does it match ", ca4, nmgroup:match(ca4))
print("Does it match ", ca5, nmgroup:match(ca5))

ca6=iputils.newca("fe80::1")
print("Does it match ", ca6, nmgroup:match(ca6))
```

## CNAME chain resolution
It may be useful to return a CNAME record for Lua, and then have the
PowerDNS Recursor continue resolving that CNAME.  This can be achieved by
returning: "followCNAMERecords", 0, {{qtype=pdns.CNAME,
content="www.powerdns.com"}}.  This indicates an rcode of 0 and the records
to put in the record.  But the first string instructs PowerDNS to complete
the CNAME chain.  Available since 3.6.


## Some sample scripts
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
lethalgroup=iputils.newnmgroup()
lethalgroup:add("192.121.121.0/24") -- touch these nameservers and you die

blockset=iputils.newipset() -- which client IP addresses we block

function preoutquery(remoteip, domain, qtype)
--	print("pdns wants to ask "..remoteip:tostring().." about "..domain.." "..qtype.." on behalf of requestor "..getlocaladdress())
	if(lethalgroup:match(remoteip))
	then
--		print("We matched the group "..lethalgroup:tostring().."!", "killing query dead & adding requestor "..getlocaladdress().." to block list")
		blockset[iputils.newca(getlocaladdress())]=1
		return -3,{} --   -3 means 'kill'
	end
	return -1,{}         --   -1 means 'no opinion'
end


local delcount=0

function ipfilter(remoteip)
	delcount=delcount+1
	
	if((delcount % 10000)==0)
	then
--		print("Clearing blockset!")
		blockset=iputils.newipset()  -- clear it
	end
	
	if(blockset[remoteip] ~= nil) then
		return 1         -- block!
	end
	return -1                -- no opinion
end
```

Every 10000 queries, the block set is emptied. 
