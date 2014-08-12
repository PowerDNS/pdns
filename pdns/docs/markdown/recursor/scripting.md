# Scripting The Recursor
As of version 3.1.7 of the PowerDNS Recursor, it is possible to modify resolving behaviour using simple scripts written in the [Lua](http://www.lua.org) programming language.

These scripts can be used to quickly override dangerous domains, fix things that are wrong, for load balancing or for legal or commercial purposes.

As of 3.1.7, queries can be intercepted in two places: before the resolving logic starts to work, plus after the resolving process failed to find a correct answer for a domain.

## Configuring Lua scripts
In order to load scripts, the PowerDNS Recursor must have Lua support built in. The packages distributed from the PowerDNS website have this language enabled, other distributions may differ. To compile with Lua support, use: `LUA=1 make` or `LUA=1 gmake` as the case may be. Paths to the Lua include files and binaries may be found near the top of the `Makefile`.

If Lua support is available, a script can be configured either via the configuration file, or at runtime via the `rec_control` tool. Scripts can be reloaded or unloaded at runtime with no interruption in operations. If a new script contains syntax errors, the old script remains in force.

On the command line, or in the configuration file, the setting `lua-dns-script` can be used to supply a full path to a 'lua' script.

At runtime, `rec_control reload-lua-script` can be used to either reload the script from its current location, or, when passed a new file name, load one from a new location. A failure to parse the new script will leave the old script in working order.

Finally, `rec_control unload-lua-script` can be used to remove the currently installed script, and revert to unmodified behaviour.

## Writing Lua PowerDNS Recursor scripts
Once a script is loaded, PowerDNS looks for several functions, as detailed below. All of these functions are optional.

### `preresolve ( remoteip, domain, qtype )`
is called before any DNS resolution is attempted, and if this function indicates it, it can supply a direct answer to the DNS query, overriding the internet. This is useful to combat botnets, or to disable domains unacceptable to an organization for whatever reason.

### `postresolve ( remoteip, domain, qtype, records, origrcode )`
is called right before returning a response to a client (and, unless `setvariable()` is called, to the packet cache too). It allows inspection and modification of almost any detail in the return packet. Available since version 3.4.

### `function nxdomain ( remoteip, domain, qtype )`
is called after the DNS resolution process has run its course, but ended in an 'NXDOMAIN' situation, indicating that the domain or the specific record does not exist. This can be used for various purposes.

### `function nodata ( remoteip, domain, qtype, records )`
is just like `nxdomain`, except it gets called when a domain exists, but the requested type does not. This is where one would implement DNS64. Available since version 3.4.

All these functions are passed the IP address of the requester, plus the name and type being requested. In return, these functions indicate if they have taken over the request, or want to let normal proceedings take their course.

**Warning**: In development versions of the PowerDNS Recursor, versions which were never released except as for testing purposes, these functions had a fourth parameter: localip This parameter has been replaced by `getlocaladdress()`, for which see below.

If a function has taken over a request, it should return an rcode (usually 0), and specify a table with records to be put in the answer section of a packet. An interesting rcode is NXDOMAIN (3, or `pdns.NXDOMAIN`), which specifies the non-existence of a domain. Returning -1 and an empty table signifies that the function chose not to intervene.

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

**Warning**: Please do NOT use the above sample script in production! Responsible NXDomain redirection requires more attention to detail.

Note that the domain is passed to the Lua function terminated by a '.'. A more complete sample script is provided as `powerdns-example-script.lua` in the PowerDNS Recursor distribution.

The answer content format is (nearly) identical to the storage in the PowerDNS Authoritative Server database, or as in zone files. The exception is that, unlike in the database, there is no 'prio' field, which means that an MX record with priority 25 pointing to 'smtp.example.net' would be encoded as '25 smtp.example.net.'.

Useful return 'rcodes' include 0 for "no error", `pdns.NXDOMAIN` for "NXDOMAIN", `pdns.DROP` to drop the question from further processing (since 3.6, and such a drop is accounted in the 'policy-drops' metric).

Fields that can be set in the return table include:

* content: Content of the record, as specified above in 'zone file format'. No default, mandatory field.
* place: Place of this record. Defaults to 1, indicating 'Answer' section. Can also be 2, for Authority of 3 for Additional. When using this rare feature, always emit records with 'Place' in ascending order. This field is usually not needed.
* qname: qname of the answer, the 'name' of the record. Defaults to the name of the query, which is almost always correct except when specifying additional records or rolling out a CNAME chain.
* qtype: Currently the numerical qtype of the answer, defaulting to '1' which is an A record. Can be also be specified as `pdns.A`, or `pdns.CNAME` etc.
* ttl: Time to live of a record. Defaults to 3600. Be sure not to specify differing TTLs within answers with an identical qname. While this will be encoded in DNS, actual results may be undesired.
* qclass: Query-Class of a record. Defaults to 1 (IN). Be sure to always return the correct qclass in each record! Valid query-classes are 1 (IN), 3 (CHAOS), 254 (NONE) and 255 (ANY).

**Warning**: Only the IN class (1) is fully supported!
**Warning**: The result table must have indexes that start at 1! Otherwise the first or confusingly the last entry of the table will be ignored. A useful technique is to return data using: `return 0, {{qtype=1, content="192.0.2.4"}, {qtype=1, content="4.3.2.1"}}` as this will get the numbering right automatically.

The function `matchnetmask(ip, netmask1, netmask2..)` (or `matchnetmask(ip, {netmask1, netmask2})`) is available to match incoming queries against a number of netmasks. If any of these match, the function returns true.

To log messages with the main PowerDNS Recursor process, use `pdnslog(message)`. Available since version 3.2. pdnslog can also write out to a syslog loglevel if specified. Use `pdnslog(message, pdns.loglevels.LEVEL)` with the correct pdns.loglevels entry. Entries are listed in the following table:

| | |
|:--||:--|
|All|pdns.loglevels.All|
|NTLog|pdns.loglevels.NTLog|
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

To indicate that an answer should not be cached in the packet cache, use `setvariable()`. Available since version 3.3.

To get fake AAAA records for DNS64 usage, use `return "getFakeAAAARecords", domain, "fe80::21b:77ff:0:0"`. Available since version 3.4.

## CNAME chain resolution
It may be useful to return a CNAME record for Lua, and then have the PowerDNS Recursor continue resolving that CNAME. This can be achieved by returning: "followCNAMERecords", 0, {{qtype=pdns.CNAME, content="www.powerdns.com"}}. This indicates an rcode of 0 and the records to put in the record. But the first string instruct PowerDNS to complete the CNAME chain. Available since 3.6.
