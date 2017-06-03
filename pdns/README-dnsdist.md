dnsdist
-------
`dnsdist` is a highly DNS-, DoS- and abuse-aware loadbalancer. Its goal in
life is to route traffic to the best server, delivering top performance
to legitimate users while shunting or blocking abusive traffic.

`dnsdist` is dynamic, in the sense that its configuration can be changed at
runtime, and that its statistics can be queried from a console-like
interface.

Compiling
---------
`dnsdist` depends on boost, Lua or LuaJIT and a pretty recent C++
compiler (g++ 4.8 or higher, clang 3.5 or higher). It can optionally use libsodium
for encrypted communications with its client, protobuf for remote logging and re2
for regular expression matching.

Should `dnsdist` be run on a system with systemd, it is highly recommended to have
the systemd header files (`libsystemd-dev` on Debian and `systemd-devel` on CentOS)
installed to have `dnsdist` support `systemd-notify`.

To compile on CentOS 6 / RHEL6, use this script to install a working compiler:

```
wget -O /etc/yum.repos.d/slc6-devtoolset.repo http://linuxsoft.cern.ch/cern/devtoolset/slc6-devtoolset.repo
yum install devtoolset-2
scl enable devtoolset-2 bash
./configure
make
```

To build on OS X, `./configure LIBEDIT_LIBS='-L/usr/lib -ledit' LIBEDIT_CFLAGS=-I/usr/include/editline`

To build on OpenBSD, `./configure CXX=eg++ CPP=ecpp LIBEDIT_LIBS='-ledit -lcurses' LIBEDIT_CFLAGS=' '`

On other recent platforms, installing a Lua and the system C++ compiler should be enough. 

`dnsdist` can drop privileges using the `--uid` and `--gid` command line switches
to ensure it does not run with root privileges after binding its listening sockets.
It is highly recommended to create a system user and group for `dnsdist`. Note that
most packaged versions of `dnsdist` already create this user.

Packaged
--------
We build packages for `dnsdist` on our [repositories](https://repo.powerdns.com). In addition
`dnsdist` [has been packaged for FreeBSD](https://freshports.org/dns/dnsdist).

Examples
--------

The absolute minimum configuration:

```
# dnsdist 2001:4860:4860::8888 8.8.8.8
```

This will listen on 0.0.0.0:53 and forward queries to the two listed IP
addresses, with a sensible load balancing policy.

Here is a more complete configuration:

```
$ cat /etc/dnsdist.conf
newServer({address="2001:4860:4860::8888", qps=1})
newServer({address="2001:4860:4860::8844", qps=1})
newServer({address="2620:0:ccc::2", qps=10})
newServer({address="2620:0:ccd::2", name="dns1", qps=10})
newServer("192.168.1.2")
setServerPolicy(firstAvailable) -- first server within its QPS limit

$ dnsdist --local=0.0.0.0:5200
Marking downstream [2001:4860:4860::8888]:53 as 'up'
Marking downstream [2001:4860:4860::8844]:53 as 'up'
Marking downstream [2620:0:ccc::2]:53 as 'up'
Marking downstream [2620:0:ccd::2]:53 as 'up'
Marking downstream 192.168.1.2:53 as 'up'
Listening on 0.0.0.0:5200
> 
```

We can now send queries to port 5200, and get answers:

```
$ dig -t aaaa powerdns.com @127.0.0.1 -p 5200 +short
2001:888:2000:1d::2
```

Note that `dnsdist` offered us a prompt above, and on it we can get some
statistics:

```
> showServers()
#   Address                   State     Qps    Qlim Ord Wt    Queries   Drops Drate   Lat Pools
0   [2001:4860:4860::8888]:53    up     0.0       1   1  1          1       0   0.0   0.0
1   [2001:4860:4860::8844]:53    up     0.0       1   1  1          0       0   0.0   0.0
2   [2620:0:ccc::2]:53           up     0.0      10   1  1          0       0   0.0   0.0
3   [2620:0:ccd::2]:53           up     0.0      10   1  1          0       0   0.0   0.0
4   192.168.1.2:53               up     0.0       0   1  1          0       0   0.0   0.0
All                                     0.0                         1       0     
```

Here we also see our configuration. 5 downstream servers have been configured, of
which the first 4 have a QPS limit (of 1, 1, 10, 10 and 0 -which means unlimited- queries per second,
respectively). The final server has no limit, which we can easily test:

```
$ for a in {0..1000}; do dig powerdns.com @127.0.0.1 -p 5200 +noall > /dev/null; done
> showServers()
#   Address                   State     Qps    Qlim Ord Wt    Queries   Drops Drate   Lat Pools
0   [2001:4860:4860::8888]:53    up     1.0       1   1  1          7       0   0.0   1.6
1   [2001:4860:4860::8844]:53    up     1.0       1   1  1          6       0   0.0   0.6
2   [2620:0:ccc::2]:53           up    10.3      10   1  1         64       0   0.0   2.4
3   [2620:0:ccd::2]:53           up    10.3      10   1  1         63       0   0.0   2.4
4   192.168.1.2:53               up   125.8       0   1  1        671       0   0.0   0.4
All                                   145.0                       811       0     
```

Note that the first 4 servers were all limited to near their configured QPS,
and that our final server was taking up most of the traffic. No queries were
dropped, and all servers remain up.

To force a server down, try:

```
> getServer(0):setDown()
> showServers()
#   Address                   State     Qps    Qlim Ord Wt    Queries   Drops Drate   Lat Pools
0   [2001:4860:4860::8888]:53  DOWN     0.0       1   1  1          8       0   0.0   0.0 
...
```

The 'DOWN' in all caps means it was forced down. A lower case 'down'
would have meant that `dnsdist` itself had concluded the server was down.
Similarly, setUp() forces a server to be up, and setAuto() returns it to the
default availability probing.

To change the QPS for a server:
```
> getServer(0):setQPS(1000)
```

By default, the availability of a downstream server is checked by regularly
sending an A query for `a.root-servers.net.`. A different query type and target
can be specified by passing, respectively, the `checkType` and `checkName`
parameters to `newServer`. The default behavior is to consider any valid response
with an RCODE different from ServFail as valid. If the `mustResolve` parameter
of `newServer` is set to true, a response will only be considered valid if
its RCODE differs from NXDomain, ServFail and Refused.
The number of health check failures before a server is considered down is
configurable via the `maxCheckFailures` parameter, defaulting to 1.
The `CD` flag can be set on the query by setting `setCD` to true.

```
newServer({address="192.0.2.1", checkType="AAAA", checkName="a.root-servers.net.", mustResolve=true})
```

In order to provide the downstream server with the address of the real client,
or at least the one talking to `dnsdist`, the `useClientSubnet` parameter can be used
when declaring a new server. This parameter indicates whether an EDNS Client Subnet option
should be added to the request. If the incoming request already contains an EDNS Client Subnet value,
it will not be overridden unless `setECSOverride()` is set to true.
The default source prefix-length is 24 for IPv4 and 56 for IPv6, meaning that for a query
received from 192.0.2.42, the EDNS Client Subnet value sent to the backend will
be 192.0.2.0/24. This can be changed with:
```
> setECSSourcePrefixV4(24)
> setECSSourcePrefixV6(56)
```

In addition to the global settings, rules and Lua bindings can alter this behavior per query:

* calling `DisableECSAction()` or setting `dq.useECS` to false prevents the sending of the ECS option
* calling `ECSOverrideAction(bool)` or setting `dq.ecsOverride` will override the global `setECSOverride()` value
* calling `ECSPrefixLengthAction(v4, v6)` or setting `dq.ecsPrefixLength` will override the global
`setECSSourcePrefixV4()` and `setECSSourcePrefixV6()` values

In effect this means that for the EDNS Client Subnet option to be added to the request, `useClientSubnet`
should be set to true for the backend used (default to false) and ECS should not have been disabled by calling
`DisableECSAction()` or setting `dq.useECS` to false (default to true).

TCP timeouts
------------

By default, a 2 second timeout is enforced on the TCP connection from the client,
meaning that a connection will be closed if the query cannot be read in less than 2 seconds
or if the answer cannot be sent in less than 2s. This can be configured with:
```
> setTCPRecvTimeout(5)
> setTCPSendTimeout(5)
```

The same kind of timeouts are enforced on the TCP connections to the downstream servers.
The default value of 30 seconds can be modified by passing the `tcpRecvTimeout` and `tcpSendTimeout`
parameters to `newServer`, with an additional `tcpConnectTimeout` parameter controlling
the connection timeout (5s by default). If the TCP connection to a downstream server fails, `dnsdist`
will try to establish a new one up to `retries` times before giving up.
```
newServer({address="192.0.2.1", tcpConnectTimeout=5, tcpRecvTimeout=10, tcpSendTimeout=10, retries=5})
```

Source address
--------------

In multi-homed setups, it can be useful to be able to select the source address or the outgoing
interface used by `dnsdist` to contact a downstream server.
This can be done by using the `source` parameter:
```
newServer({address="192.0.2.1", source="192.0.2.127"})
newServer({address="192.0.2.1", source="eth1"})
newServer({address="192.0.2.1", source="192.0.2.127@eth1"})
```

The supported values for `source` are:

 * an IPv4 or IPv6 address, which must exist on the system
 * an interface name
 * an IPv4 or IPv6 address followed by '@' then an interface name

Specifying the interface name is only supported on system having `IP_PKTINFO`.


Configuration management
------------------------
At startup, configuration is read from the command line and the
configuration file. The config can also be inspected and changed from the
console. Sadly, our architecture does not allow us to serialize the running
configuration for you. However, we do try to offer the next best thing:
`delta()`.

`delta()` shows all commands entered that changed the configuration. So
adding a new downstream server with `newServer()` would show up, but
`showServers()` or even `delta()` itself would not.

It is suggested to study the output of `delta()` carefully before appending
it to your configuration file. 

```
> setACL("192.0.2.0/24")
> showACL()
192.0.2.0/24
> delta()
-- Wed Dec 23 2015 15:15:35 CET
setACL("192.0.2.0/24")
> addACL("127.0.0.1/8")
> showACL()
192.0.2.0/24
127.0.0.1/8
> delta()
-- Wed Dec 23 2015 15:15:35 CET
setACL("192.0.2.0/24")
-- Wed Dec 23 2015 15:15:44 CET
addACL("127.0.0.1/8")
>
```


Webserver
---------
To visually interact with `dnsdist`, try adding:
```
webserver("127.0.0.1:8083", "supersecretpassword", "supersecretAPIkey")
```

to the configuration, and point your browser at http://127.0.0.1:8083 and
log in with any username, and that password. Enjoy!

By default, our web server sends some security-related headers:

 * X-Content-Type-Options: nosniff
 * X-Frame-Options: deny
 * X-Permitted-Cross-Domain-Policies: none
 * X-XSS-Protection: 1; mode=block
 * Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'

You can override those headers, or add custom headers by using the last parameter to
`webserver()`. For example, to remove the `X-Frame-Options` header and add a
`X-Custom` one:
```
webserver("127.0.0.1:8080", "supersecret", "apikey", {["X-Frame-Options"]= "", ["X-Custom"]="custom"})
```


Server pools
------------
Now for some cool stuff. Let's say we know we're getting a whole bunch of
traffic for a domain used in DoS attacks, for example 'sh43354.cn'. We can
do two things with this kind of traffic. Either we block it outright, like
this:

```
> addDomainBlock("sh43354.cn.")
```

Or we configure a server pool dedicated to receiving the nasty stuff:

```
> newServer({address="192.168.1.3", pool="abuse"})
> addPoolRule({"sh43353.cn.", "ezdns.it."}, "abuse")
```

The wonderful thing about this last solution is that it can also be used for
things where a domain might possibly be legit, but it is still causing load
on the system and slowing down the Internet for everyone. With such an abuse
server, 'bad traffic' still gets a chance of an answer, but without
impacting the rest of the world (too much).

We can similarly add clients to the abuse server:

```
> addPoolRule({"192.168.12.0/24", "192.168.13.14"}, "abuse")
```

To define a pool that should receive only a QPS-limited amount of traffic, do:

```
> addQPSPoolRule("com.", 10000, "gtld-cluster")
```

Traffic exceeding the QPS limit will not match that rule, and subsequent
rules will apply normally.

Both `addDomainBlock` and `addPoolRule` end up the list of Rules 
and Actions (for which see below).

Servers can be added to or removed from pools with:
```
> getServer(7):addPool("abuse")
> getServer(4):rmPool("abuse")
```


Rules
-----
Rules can be inspected with `showRules()`, and can be deleted with
`rmRule()`.  Rules are evaluated in order, and this order can be changed
with `mvRule(from, to)` (see below for exact semantics).

Rules have selectors and actions. Current selectors are:

 * Source address
 * Query type
 * Query domain
 * QPS Limit total
 * QPS Limit per IP address or subnet
 * QClass (QClassRule)
 * QName (QNameRule)
 * QType (QTypeRule)
 * RegexRule on query name
 * RE2Rule on query name (optional)
 * Response code
 * Packet requests DNSSEC processing
 * Packet requests recursion
 * Query received over UDP or TCP
 * Opcode (OpcodeRule)
 * Number of entries in a given section (RecordsCountRule)
 * Number of entries of a specific type in a given section (RecordsTypeCountRule)
 * Presence of trailing data (TrailingDataRule)
 * Number of labels in the qname (QNameLabelsCountRule)
 * Wire length of the qname (QNameWireLengthRule)

Special rules are:

 * `AndRule{rule1, rule2}`, which only matches if all of its subrules match
 * `OrRule{rule1, rule2}`, which matches if at least one of its subrules match
 * `NotRule(rule)`, which matches if its subrule does not match

Current actions are:

 * Drop (DropAction)
 * Route to a pool (PoolAction)
 * Return with TC=1 (truncated, i.e., instruction to retry with TCP)
 * Force a ServFail, NotImp or Refused answer
 * Send out a crafted response (NXDOMAIN or "real" data)
 * Delay a response by n milliseconds (DelayAction), over UDP only
 * Modify query to clear the RD or CD bit
 * Add the source MAC address to the query (MacAddrAction, only supported on Linux)
 * Skip the cache, if any
 * Log query content to a remote server (RemoteLogAction)
 * Alter the EDNS Client Subnet parameters (DisableECSAction, ECSOverrideAction, ECSPrefixLengthAction)
 * Send an SNMP trap (SNMPTrapAction)

Current response actions are:

 * Allow (AllowResponseAction)
 * Delay a response by n milliseconds (DelayResponseAction), over UDP only
 * Drop (DropResponseAction)
 * Log response content to a remote server (RemoteLogResponseAction)
 * Send an SNMP trap (SNMPTrapResponseAction)

Rules can be added via:

 * addAction(DNS rule, DNS Action)
 * addAnyTCRule()
 * addDelay(DNS rule, delay in milliseconds)
 * addDisableValidationRule(DNS rule)
 * addDomainBlock(domain)
 * addDomainSpoof(domain, IPv4[, IPv6]) or addDomainSpoof(domain, {IP, IP, IP..})
 * addDomainCNAMESpoof(domain, CNAME)
 * addLuaAction(DNS rule, Lua function)
 * addNoRecurseRule(DNS rule)
 * addPoolRule(DNS rule, destination pool)
 * addQPSLimit(DNS rule, qps limit)
 * addQPSPoolRule(DNS rule, qps limit, destination pool)

Response rules can be added via:

 * addResponseAction(DNS rule, DNS Response Action)
 * AddLuaResponseAction(DNS rule, Lua function)

Cache Hit Response rules, triggered on a cache hit, can be added via:

 * addCacheHitResponseAction(DNS rule, DNS Response Action)

A DNS rule can be:

 * A string that is either a domain name or netmask
 * A list of strings that are either domain names or netmasks
 * A DNSName
 * A list of DNSNames
 * an AllRule
 * an AndRule
 * a DNSSECRule
 * a MaxQPSIPRule
 * a MaxQPSRule
 * a NetmaskGroupRule
 * a NotRule
 * an OpcodeRule
 * an OrRule
 * a QClassRule
 * a QNameLabelsCountRule
 * a QNameRule
 * a QNameWireLengthRule
 * a QTypeRule
 * a RCodeRule
 * a RDRule
 * a RegexRule
 * a RE2Rule
 * a RecordsCountRule
 * a RecordsTypeCountRule
 * a SuffixMatchNodeRule
 * a TCPRule
 * a TrailingDataRule

Some specific actions do not stop the processing when they match, contrary to all other actions:

 * Delay
 * DisableECS
 * Disable Validation
 * ECSOverride
 * ECSPrefixLength
 * Log
 * MacAddr
 * No Recurse
 * SNMP Trap
 * and of course None

A convenience function `makeRule()` is supplied which will make a NetmaskGroupRule for you or a SuffixMatchNodeRule
depending on how you call it. `makeRule("0.0.0.0/0")` will for example match all IPv4 traffic, `makeRule({"be","nl","lu"})` will
match all Benelux DNS traffic.

All the current rules can be removed at once with:

```
> clearRules()
```

It is also possible to replace the current rules by a list of new ones in a
single operation with `setRules()`:

```
> setRules( { newRuleAction(TCPRule(), AllowAction()), newRuleAction(AllRule(), DropAction()) } )
```


More power
----------
More powerful things can be achieved by defining a function called
`blockFilter()` in the configuration file, which can decide to drop traffic
on any reason it wants. If you return 'true' from there, the query will get
blocked.

A demo on how to do this and many other things can be found on
https://github.com/powerdns/pdns/blob/master/pdns/dnsdistconf.lua and
the exact definition of `blockFilter()` is at the end of this document.

ANY or whatever to TC
---------------------
The `blockFilter()` also gets passed read/writable copy of the DNS Header,
via `dq.dh`.
If you invoke setQR(1) on that, `dnsdist` knows you turned the packet into
a response, and will send the answer directly to the original client.

If you also called setTC(1), this will tell the remote client to move to
TCP, and in this way you can implement ANY-to-TCP even for downstream
servers that lack this feature.

Note that calling `addAnyTCRule()` achieves the same thing, without
involving Lua.

Rules for traffic exceeding QPS limits
--------------------------------------
Traffic that exceeds a QPS limit, in total or per IP (subnet) can be matched by a rule.

For example:

```
addDelay(MaxQPSIPRule(5, 32, 48), 100)
```

This measures traffic per IPv4 address and per /48 of IPv6, and if traffic for such 
an address (range) exceeds 5 qps, it gets delayed by 100ms.

As another example:

```
addAction(MaxQPSIPRule(5), NoRecurseAction())
```

This strips the Recursion Desired (RD) bit from any traffic per IPv4 or IPv6 /64 
that exceeds 5 qps. This means any those traffic bins is allowed to make a recursor do 'work'
for only 5 qps.

If this is not enough, try:

```
addAction(MaxQPSIPRule(5), DropAction())
-- or
addAction(MaxQPSIPRule(5), TCAction())
```

This will respectively drop traffic exceeding that 5 QPS limit per IP or range, or return it with TC=1, forcing
clients to fall back to TCP.

To turn this per IP or range limit into a global limit, use NotRule(MaxQPSRule(5000)) instead of MaxQPSIPRule.

TeeAction
---------
This action sends off a copy of a UDP query to another server, and keeps statistics
on the responses received. Sample use:

```
> addAction(AllRule(), TeeAction("192.168.1.54"))
> getAction(0):printStats()
refuseds	0
nxdomains	0
noerrors	0
servfails	0
recv-errors	0
tcp-drops	0
responses	0
other-rcode	0
send-errors	0
queries	0
```

It is also possible to share a TeeAction between several rules. Statistics
will be combined in that case.

Lua actions in rules
--------------------
While we can pass every packet through the `blockFilter()` functions, it is also
possible to configure `dnsdist` to only hand off some packets for Lua inspection. 
If you think Lua is too slow for your query load, or if you are doing heavy processing in Lua, 
this may make sense.

To select specific packets for Lua attention, use `addLuaAction(x, func)`,
where x is either a netmask, or a domain suffix, or a table of netmasks or a
table of domain suffixes.  This is identical to how `addPoolRule()` selects.

The function should look like this:
```
function luarule(dq)
        if(dq.qtype==35) -- NAPTR
        then
                return DNSAction.Pool, "abuse" -- send to abuse pool
        else
                return DNSAction.None, ""      -- no action
        end
end
```

Valid return values for `LuaAction` functions are:

 * DNSAction.Allow: let the query pass, skipping other rules
 * DNSAction.Delay: delay the response for the specified milliseconds (UDP-only), continue to the next rule
 * DNSAction.Drop: drop the query
 * DNSAction.HeaderModify: indicate that the query has been turned into a response
 * DNSAction.None: continue to the next rule
 * DNSAction.Nxdomain: return a response with a NXDomain rcode
 * DNSAction.Pool: use the specified pool to forward this query
 * DNSAction.Refused: return a response with a Refused rcode
 * DNSAction.Spoof: spoof the response using the supplied IPv4 (A), IPv6 (AAAA) or string (CNAME) value

The same feature exists to hand off some responses for Lua inspection, using `addLuaResponseAction(x, func)`.

DNSSEC
------
To provide DNSSEC service from a separate pool, try:
```
newServer({address="2001:888:2000:1d::2", pool="dnssec"})
newServer({address="2a01:4f8:110:4389::2", pool="dnssec"})
setDNSSECPool("dnssec")
topRule()
```

This routes all queries with a DNSSEC OK (DO) or CD bit set to on to the "dnssec" pool.
The final `topRule()` command moves this rule to the top, so it gets evaluated first.

Regular Expressions
-------------------
`RegexRule()` matches a regular expression on the query name, and it works like this:

```
addAction(RegexRule("[0-9]{5,}"), DelayAction(750)) -- milliseconds
addAction(RegexRule("[0-9]{4,}\\.cn$"), DropAction())
```

This delays any query for a domain name with 5 or more consecutive digits in it.
The second rule drops anything with more than 4 consecutive digits within a .CN domain.

Note that the query name is presented without a trailing dot to the regex.
The regex is applied case insensitively. 

Alternatively, if compiled in, RE2Rule provides similar functionality, but against libre2.

Inspecting live traffic
-----------------------
This is still much in flux, but for now, try:

 * `grepq(Netmask|DNS Name|100ms [, n])`: shows the last n queries and responses matching the specified client address or range (Netmask), or the specified DNS Name, or slower than 100ms
 * `grepq({"::1", "powerdns.com", "100ms"} [, n])`: shows the last n queries and responses matching the specified client address AND range (Netmask) AND the specified DNS Name AND slower than 100ms
 * `topBandwidth(top)`: show top-`top` clients that consume the most bandwidth over length of ringbuffer
 * `topClients(n)`: show top-`n` clients sending the most queries over length of ringbuffer
 * `topQueries(20)`: shows the top-20 queries
 * `topQueries(20,2)`: shows the top-20 two-level domain queries (so `topQueries(20,1)` only shows TLDs)
 * `topResponses(20, 2)`: top-20 servfail responses (use ,3 for NXDOMAIN)
 * `topSlow([top][, limit][, labels])`: show `top` queries slower than `limit` milliseconds, grouped by last `labels` labels

For example:
```
> grepq("127.0.0.1/24")
Time    Client                                          Server       ID    Name                      Type  Lat.   TC RD AA Rcode
-11.9   127.0.0.1:52599                                              16127 nxdomain.powerdns.com.    A               RD    Question
-11.7   127.0.0.1:52599                                 127.0.0.1:53 16127 nxdomain.powerdns.com.    A     175.6     RD    Non-Existent domain
> grepq("powerdns.com")
Time    Client                                          Server       ID    Name                      Type  Lat.   TC RD AA Rcode
-38.7   127.0.0.1:52599                                              16127 nxdomain.powerdns.com.    A               RD    Question
-38.6   127.0.0.1:52599                                 127.0.0.1:53 16127 nxdomain.powerdns.com.    A     175.6     RD    Non-Existent domain
```

Live histogram of latency
-------------------------
```
> showResponseLatency()
Average response latency: 78.84 msec
   msec	
   0.10	
   0.20	.
   0.40	**********************
   0.80	***********
   1.60	.
   3.20	
   6.40	.
  12.80	*
  25.60	*
  51.20	*
 102.40	**********************************************************************
 204.80	*************************
 409.60	**
 819.20	:
1638.40	.
```

Where : stands for 'half a star' and . for 'less than half a star, but
something was there'.

Per domain or subnet QPS limiting
---------------------------------
If certain domains or source addresses are generating onerous amounts of
traffic, you can put ceilings on the amount of traffic you are willing to
forward:

```
> addQPSLimit("h4xorbooter.xyz.", 10)
> addQPSLimit({"130.161.0.0/16", "145.14.0.0/16"} , 20)
> addQPSLimit({"nl.", "be."}, 1)
> showRules()
#     Matches Rule                                               Action
0           0 h4xorbooter.xyz.                                   qps limit to 10
1           0 130.161.0.0/16, 145.14.0.0/16                      qps limit to 20
2           0 nl., be.                                           qps limit to 1
```

To delete a limit (or a rule in general):
```
> rmRule(1)
> showRules()
#     Matches Rule                                               Action
0           0 h4xorbooter.xyz.                                   qps limit to 10
1           0 nl., be.                                           qps limit to 1
```

Delaying answers
----------------
Sometimes, runaway scripts will hammer your servers with back-to-back
queries.  While it is possible to drop such packets, this may paradoxically
lead to more traffic. 

An attractive middleground is to delay answers to such back-to-back queries,
causing a slowdown on the side of the source of the traffic.

To do so, use:
```
> addDelay("yourdomain.in.ua.", 500)
> addDelay({"65.55.37.0/24"}, 500)
```
This will delay responses for questions to the mentioned domain, or coming
from the configured subnet, by half a second.

Like the QPSLimits and other rules, the delaying instructions can be
inspected or edited using `showRules()`, `rmRule()`, `topRule()`, `mvRule()` etc.

Dynamic load balancing
----------------------
The default load balancing policy is called `leastOutstanding`, which means
we pick the server with the least queries 'in the air' (and within those,
the one with the lowest `order`, and within those, the one with the lowest latency).

Another policy, `firstAvailable`, picks the first server that has not
exceeded its QPS limit. If all servers are above their QPS limit, a
server is selected based on the `leastOutstanding` policy. For now this
is the only policy using the QPS limit.

A further policy, `wrandom` assigns queries randomly, but based on the
`weight` parameter passed to `newServer`. `whashed` is a similar weighted policy,
but assigns questions with identical hash to identical servers, allowing for
better cache concentration ('sticky queries').

If you don't like the default policies you can create your own, like this
for example:

```
counter=0
function luaroundrobin(servers, dq)
	 counter=counter+1
	 return servers[1+(counter % #servers)]
end

setServerPolicyLua("luaroundrobin", luaroundrobin)
```

Incidentally, this is similar to setting: `setServerPolicy(roundrobin)`
which uses the C++ based roundrobin policy.

Lua server policies 
-------------------
If the built in rules do not suffice to pick a server pool, full flexibility is available from Lua. For example:

```
newServer("192.168.1.2")
newServer({address="8.8.4.4", pool="numbered"})

function splitSetup(servers, dq)
         if(string.match(dq.qname:toString(), "%d"))
         then
                print("numbered pool")
                return leastOutstanding.policy(getPoolServers("numbered"), dq)
         else
                print("standard pool")
                return leastOutstanding.policy(servers, dq)
         end
end

setServerPolicyLua("splitsetup", splitSetup)
```

This will forward queries containing a number to the pool of "numbered" 
servers, and will apply the default load balancing policy to all other
queries.

Dynamic Rule Generation
-----------------------
To set dynamic rules, based on recent traffic, define a function called `maintenance()` in Lua. It will
get called every second, and from this function you can set rules to block traffic based on statistics.
More exactly, the thread handling the `maintenance()` function will sleep for one second between each
invocation, so if the function takes several seconds to complete it will not be invoked exactly every second.

As an example:

```
function maintenance()
	addDynBlocks(exceedQRate(20, 10), "Exceeded query rate", 60)
end
```

This will dynamically block all hosts that exceeded 20 queries/s as measured
over the past 10 seconds, and the dynamic block will last for 60 seconds.

Dynamic blocks in force are displayed with `showDynBlocks()` and can be cleared
with `clearDynBlocks()`. Full set of `exceed` functions is listed in the table of
all functions below. They return a table whose key is a `ComboAddress` object,
representing the client's source address, and whose value is an integer representing
the number of queries matching the corresponding condition (for example the
`qtype` for `exceedQTypeRate()`, `rcode` for `exceedServFails()`).

Dynamic blocks drop matched queries by default, but this behavior can be changed
with `setDynBlocksAction()`. For example, to send a REFUSED code instead of droppping
the query:

```
setDynBlocksAction(DNSAction.Refused)
```

Running it for real
-------------------
First run on the command line, and generate a key:

```
# dnsdist
> makeKey()
setKey("sepuCcHcQnSAZgNbNPCCpDWbujZ5esZJmrt/wh6ldkQ=")
```

Now add this setKey line to `dnsdist.conf`, and also add:

```
controlSocket("0.0.0.0") -- or add portnumber too
```

Then start `dnsdist` as a daemon, and then connect to it:
```
# dnsdist --daemon
# dnsdist --client
> 
```

Please note that, without libsodium support, 'makeKey()' will return
setKey("plaintext") and the communication between the client and the
server will not be encrypted.

Some versions of libedit, notably the CentOS 6 one, may require the following
addition to ~/.editrc in order to support searching through the history:

```
bind "^R" em-inc-search-prev
```

ACL, who can use dnsdist
------------------------
For safety reasons, by default only private networks can use `dnsdist`, see below
how to query and change the ACL:

```
> showACL()
127.0.0.0/8
10.0.0.0/8
(...)
::1/128
fc00::/7
fe80::/10
> addACL("130.161.0.0/16")
> setACL({"::/0"}) -- resets the list to this array
> showACL()
::/0
```

Caching
-------
`dnsdist` implements a simple but effective packet cache, not enabled by default.
It is enabled per-pool, but the same cache can be shared between several pools.
The first step is to define a cache, then to assign that cache to the chosen pool,
the default one being represented by the empty string:

```
pc = newPacketCache(10000, 86400, 0, 60, 60, false)
getPool(""):setCache(pc)
```

The first parameter (10000) is the maximum number of entries stored in the cache, and is the
only one required. The second, third, fourth and fifth parameters are optional and in seconds.
The second one (86400) is the maximum lifetime of an entry in the cache, the third one (0) is
the minimum TTL an entry should have to be considered for insertion in the cache,
the fourth one (60) is the TTL used for a Server Failure or a Refused response. The fifth
one (60) is the TTL that will be used when a stale cache entry is returned. The last one
is a boolean that indicates whether the TTL of reponses should be reduced by the number of
seconds the response has been in the cache.
For performance reasons the cache will pre-allocate buckets based on the maximum number
of entries, so be careful to set the first parameter to a reasonable value. Something
along the lines of a dozen bytes per pre-allocated entry can be expected on 64-bit.
That does not mean that the memory is completely allocated up-front, the final memory
usage depending mostly on the size of cached responses and therefore varying during the
cache's lifetime. Assuming an average response size of 512 bytes, a cache size of
10000000 entries on a 64-bit host with 8GB of dedicated RAM would be a safe choice.

The `setStaleCacheEntriesTTL(n)` directive can be used to allow `dnsdist` to use
expired entries from the cache when no backend is available. Only entries that have
expired for less than `n` seconds will be used, and the returned TTL can be set
when creating a new cache with `newPacketCache()`.

A reference to the cache affected to a specific pool can be retrieved with:

```
getPool("poolname"):getCache()
```

And removed with:

```
getPool("poolname"):unsetCache()
```

Cache usage stats (hits, misses, deferred inserts and lookups, collisions)
can be displayed by using the `printStats()` method:

```
getPool("poolname"):getCache():printStats()
```

Expired cached entries can be removed from a cache using the `purgeExpired(n)`
method, which will remove expired entries from the cache until at most `n`
entries remain in the cache. For example, to remove all expired entries:

```
getPool("poolname"):getCache():purgeExpired(0)
```

Specific entries can also be removed using the `expungeByName(DNSName [, qtype=ANY, suffixMatch=false])`
method. If suffixMatch is set to true it will remove any entries below DNSName.

```
getPool("poolname"):getCache():expungeByName(newDNSName("powerdns.com"), dnsdist.A, true)
```

Finally, the `expunge(n)` method will remove all entries until at most `n`
entries remain in the cache:

```
getPool("poolname"):getCache():expunge(0)
```


Performance tuning
------------------
First, a few words about `dnsdist` architecture:

 * Each local bind has its own thread listening for incoming UDP queries
 * and its own thread listening for incoming TCP connections,
 dispatching them right away to a pool of threads
 * Each backend has its own thread listening for UDP responses
 * A maintenance thread calls the `maintenance()` Lua function every second
 if any, and is responsible for cleaning the cache
 * A health check thread checks the backends availability
 * A control thread handles console connections
 * A carbon thread exports statistics to carbon servers if needed
 * One or more webserver threads handle queries to the internal webserver

The maximum number of threads in the TCP pool is controlled by the
`setMaxTCPClientThreads()` directive, and defaults to 10. This number can be
increased to handle a large number of simultaneous TCP connections.
If all the TCP threads are busy, new TCP connections are queued while
they wait to be picked up. The maximum number of queued connections
can be configured with `setMaxTCPQueuedConnections()` and defaults to 1000.
Any value larger than 0 will cause new connections to be dropped if there are
already too many queued.
By default, every TCP worker thread has its own queue, and the incoming TCP
connections are dispatched to TCP workers on a round-robin basis. This might
cause issues if some connections are taking a very long time, since incoming
ones will be waiting until the TCP worker they have been assigned to has finished
handling its current query, while other TCP workers might be available.
The experimental `setTCPUseSinglePipe(true)` directive can be used so that all the
incoming TCP connections are put into a single queue and handled by the
first TCP worker available.

When dispatching UDP queries to backend servers, `dnsdist` keeps track of at
most `n` outstanding queries for each backend. This number `n` can be tuned by
the `setMaxUDPOutstanding()` directive, defaulting to 10240, with a maximum
value of 65535. Large installations are advised to increase the default value
at the cost of a slightly increased memory usage.

Most of the query processing is done in C++ for maximum performance,
but some operations are executed in Lua for maximum flexibility:

 * the `blockfilter()` function
 * rules added by `addLuaAction()`
 * server selection policies defined via `setServerPolicyLua()` or `newServerPolicy()`

While Lua is fast, its use should be restricted to the strict necessary in order
to achieve maximum performance, it might be worth considering using LuaJIT instead
of Lua. When Lua inspection is needed, the best course of action is to restrict
the queries sent to Lua inspection by using `addLuaAction()` instead of inspecting
all queries in the `blockfilter()` function.

`dnsdist` design choices mean that the processing of UDP queries is done by only
one thread per local bind. This is great to keep lock contention to a low level,
but might not be optimal for setups using a lot of processing power, caused for
example by a large number of complicated rules. To be able to use more CPU cores
for UDP queries processing, it is possible to use the `reuseport` parameter of
the `addLocal()` and `setLocal()` directives to be able to add several identical
local binds to `dnsdist`:

```
addLocal("192.0.2.1:53", { reusePort=true })
addLocal("192.0.2.1:53", { reusePort=true })
addLocal("192.0.2.1:53", { reusePort=true })
addLocal("192.0.2.1:53", { reusePort=true })
```

`dnsdist` will then add four identical local binds as if they were different IPs
or ports, start four threads to handle incoming queries and let the kernel load
balance those randomly to the threads, thus using four CPU cores for rules
processing. Note that this require SO_REUSEPORT support in the underlying
operating system (added for example in Linux 3.9).
Please also be aware that doing so will increase lock contention and might not
therefore scale linearly. This is especially true for Lua-intensive setups,
because Lua processing in `dnsdist` is serialized by an unique lock for all
threads.

Another possibility is to use the reuseport option to run several `dnsdist`
processes in parallel on the same host, thus avoiding the lock contention issue
at the cost of having to deal with the fact that the different processes will
not share informations, like statistics or DDoS offenders.

The UDP threads handling the responses from the backends do not use a lot of CPU,
but if needed it is also possible to add the same backend several times to the
`dnsdist` configuration to distribute the load over several responder threads.

```
newServer({address="192.0.2.127:53", name="Backend1"})
newServer({address="192.0.2.127:53", name="Backend2"})
newServer({address="192.0.2.127:53", name="Backend3"})
newServer({address="192.0.2.127:53", name="Backend4"})
```


Carbon/Graphite/Metronome
-------------------------
To emit metrics to Graphite, or any other software supporting the Carbon protocol, use:
```
carbonServer('ip-address-of-carbon-server', 'ourname', 30)
```

Where 'ourname' can be used to override your hostname, and '30' is the
reporting interval in seconds.  The last two arguments can be omitted.  The
latest version of [PowerDNS
Metronome](https://github.com/ahupowerdns/metronome) comes with attractive
graphs for `dnsdist` by default.

Query counters
-------------
When using `carbonServer`, it is also possible to send per-records statistics of
the amount of queries by using `setQueryCount(true)`. With query counting enabled,
`dnsdist` will increase a counter for every unique record or the behaviour you define
in a custom Lua function by setting `setQueryCountFilter(func)`. This filter can decide
whether to keep count on a query at all or rewrite for which query the counter will be
increased.
An example of a `QueryCountFilter` would be:

```
function filter(dq)
  qname = dq.qname:toString()

  -- don't count PTRs at all
  if(qname:match('in%-addr.arpa$')) then
    return false, ""
  end

  -- count these queries as if they were queried without leading www.
  if(qname:match('^www.')) then
    qname = qname:gsub('^www.', '')
  end

  -- count queries by default
  return true, qname
end

setQueryCountFilter(filter)
```

Valid return values for `QueryCountFilter` functions are:

* `true`: count the specified query
* `false`: don't count the query

Note that the query counters are buffered and flushed each time statistics are
sent to the carbon server. The current content of the buffer can be inspected
with `getQueryCounters()`.  If you decide to enable query counting without
`carbonServer`, make sure you implement clearing the log from `maintenance()`
by issuing `clearQueryCounters()`.

DNSCrypt
--------
`dnsdist`, when compiled with --enable-dnscrypt, can be used as a DNSCrypt server,
uncurving queries before forwarding them to downstream servers and curving responses back.
To make `dnsdist` listen to incoming DNSCrypt queries on 127.0.0.1 port 8443,
with a provider name of "2.providername", using a resolver certificate and associated key
stored respectively in the `resolver.cert` and `resolver.key` files, the `addDnsCryptBind()`
directive can be used:

```
addDNSCryptBind("127.0.0.1:8443", "2.providername", "/path/to/resolver.cert", "/path/to/resolver.key")
```

To generate the provider and resolver certificates and keys, you can simply do:

```
> generateDNSCryptProviderKeys("/path/to/providerPublic.key", "/path/to/providerPrivate.key")
Provider fingerprint is: E1D7:2108:9A59:BF8D:F101:16FA:ED5E:EA6A:9F6C:C78F:7F91:AF6B:027E:62F4:69C3:B1AA
> generateDNSCryptCertificate("/path/to/providerPrivate.key", "/path/to/resolver.cert", "/path/to/resolver.key", serial, validFrom, validUntil)
```

Note that 'validFrom' and 'validUntil' are UNIX epoch timestamps. These can
easily be calculated as 'os.time(), os.time()+2*365*86400' for example to
get a certificate that is valid for two years from now.

Ideally, the certificates and keys should be generated on an offline dedicated hardware and not on the resolver.
The resolver key should be regularly rotated and should never touch persistent storage, being stored in a tmpfs
with no swap configured.

You can display the currently configured DNSCrypt binds with:
```
> showDNSCryptBinds()
#   Address              Provider Name        Serial   Validity              P. Serial P. Validity
0   127.0.0.1:8443       2.name               14       2016-04-10 08:14:15   0         -
```

If you forgot to write down the provider fingerprint value after generating the provider keys, you can use `printDNSCryptProviderFingerprint()` to retrieve it later:
```
> printDNSCryptProviderFingerprint("/path/to/providerPublic.key")
Provider fingerprint is: E1D7:2108:9A59:BF8D:F101:16FA:ED5E:EA6A:9F6C:C78F:7F91:AF6B:027E:62F4:69C3:B1AA
```

AXFR, IXFR and NOTIFY
---------------------
When `dnsdist` is deployed in front of a master authoritative server, it might
receive AXFR or IXFR queries destined to this master. There are two issues
that can arise in this kind of setup:

 * If the master is part of a pool of servers, the first SOA query can be directed
   by `dnsdist` to a different server than the following AXFR/IXFR one, which might
   fail if the servers are not perfectly synchronised.
 * If the master only allows AXFR/IXFR based on the source address of the requestor,
   it might be confused by the fact that the source address will be the one from
   the `dnsdist` server.

The first issue can be solved by routing SOA, AXFR and IXFR requests explicitly
to the master:

```
> newServer({address="192.168.1.2", name="master", pool={"master", "otherpool"}})
> addAction(OrRule({QTypeRule(dnsdist.SOA), QTypeRule(dnsdist.AXFR), QTypeRule(dnsdist.IXFR)}), PoolAction("master"))
```

The second one might require allowing AXFR/IXFR from the `dnsdist` source address
and moving the source address check on `dnsdist`'s side:

```
> addAction(AndRule({OrRule({QTypeRule(dnsdist.AXFR), QTypeRule(dnsdist.IXFR)}), NotRule(makeRule("192.168.1.0/24"))}), RCodeAction(dnsdist.REFUSED))
```

When `dnsdist` is deployed in front of slaves, however, an issue might arise with NOTIFY
queries, because the slave will receive a notification coming from the `dnsdist` address,
and not the master's one. One way to fix this issue is to allow NOTIFY from the `dnsdist`
address on the slave side (for example with PowerDNS's `trusted-notification-proxy`) and
move the address check on `dnsdist`'s side:

```
> addAction(AndRule({OpcodeRule(DNSOpcode.Notify), NotRule(makeRule("192.168.1.0/24"))}), RCodeAction(dnsdist.REFUSED))
```

eBPF Socket Filtering
---------------------
`dnsdist` can use eBPF socket filtering on recent Linux kernels (4.1+) built with eBPF
support (`CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, ideally `CONFIG_BPF_JIT`).
This feature might require an increase of the memory limit associated to a socket, via
the `sysctl` setting `net.core.optmem_max`. When attaching an eBPF program to a socket,
the size of the program is checked against this limit, and the default value might not be
enough. Large map sizes might also require an increase of `RLIMIT_MEMLOCK`.

This feature allows `dnsdist` to ask the kernel to discard incoming packets in kernel-space
instead of them being copied to userspace just to be dropped, thus being a lot of faster.

The BPF filter can be used to block incoming queries manually:

```
> bpf = newBPFFilter(1024, 1024, 1024)
> bpf:attachToAllBinds()
> bpf:block(newCA("2001:DB8::42"))
> bpf:blockQName(newDNSName("evildomain.com"), 255)
> bpf:getStats()
[2001:DB8::42]: 0
evildomain.com. 255: 0
> bpf:unblock(newCA("2001:DB8::42"))
> bpf:unblockQName(newDNSName("evildomain.com"), 255)
> bpf:getStats()
>
```

The `blockQName()` method can be used to block queries based on the exact qname supplied,
in a case-insensitive way, and an optional qtype. Using the 255 (ANY) qtype will block all
queries for the qname, regardless of the qtype.
Contrary to source address filtering, qname filtering only works over UDP. TCP qname
filtering can be done the usual way:

```
> addAction(AndRule({TCPRule(true), makeRule("evildomain.com")}), DropAction())
```

The `attachToAllBinds()` method attaches the filter to every existing bind at runtime,
but it's also possible to define a default BPF filter at configuration time, so
it's automatically attached to every bind:

```
bpf = newBPFFilter(1024, 1024, 1024)
setDefaultBPFFilter(bpf)
```

Finally, it's also possible to attach it to specific binds at runtime:

```
> bpf = newBPFFilter(1024, 1024, 1024)
> showBinds()
#   Address              Protocol  Queries
0   [::]:53              UDP       0
1   [::]:53              TCP       0
> bd = getBind(0)
> bd:attachFilter(bpf)
```

`dnsdist` also supports adding dynamic, expiring blocks to a BPF filter:

```
bpf = newBPFFilter(1024, 1024, 1024)
setDefaultBPFFilter(bpf)
dbpf = newDynBPFFilter(bpf)
function maintenance()
        addBPFFilterDynBlocks(exceedQRate(20, 10), dbpf, 60)
        dbpf:purgeExpired()
end
```

This will dynamically block all hosts that exceeded 20 queries/s as measured
over the past 10 seconds, and the dynamic block will last for 60 seconds.

This feature has been successfully tested on Arch Linux, Arch Linux ARM,
Fedora Core 23 and Ubuntu Xenial.

SNMP support
------------
`dnsdist` supports exporting statistics and sending traps over SNMP when compiled
with `Net SNMP` support, acting as an `AgentX` subagent.
`SNMP` support is enabled via the `snmpAgent(enableTraps [, masterSocket])` directive,
where `enableTraps` is a boolean indicating whether traps should be sent and `masterSocket`
is an optional string specifying how to connect to the master agent. The default for this
last parameter is to use an Unix socket, but others options are available, such as TCP: `tcp:localhost:705`

By default, the only traps sent when `enableTraps` is set to `true` are backend status change notifications, but traps can also be sent:

 * from Lua, with `sendCustomTrap(string)` and `dq:sendTrap(string)`
 * for selected queries and responses, using `SNMPTrapAction([string])` and `SNMPTrapResponseAction([string])`

`Net SNMP snmpd` doesn't accept subagent connections by default, so to use the `SNMP`
features of `dnsdist` the following line should be added to the `snmpd.conf` configuration
file:

```
master agentx
```

In addition to that, the permissions on the resulting socket might need to be adjusted
so that the `dnsdist` user can write to it. This can be done with the following lines in
`snmpd.conf` (assuming `dnsdist` is running as `dnsdist:dnsdist`):

```
agentxperms 0700 0700 dnsdist dnsdist
```

In order to allow the retrieval of statistics via `SNMP`, `snmpd`'s access control
has to configured. A very simple `SNMPv2c` setup only needs the configuration of
a read-only community in `snmpd.conf`:

```
rocommunity dnsdist42
```

`snmpd` also supports more secure `SNMPv3` setup, using for example the `createUser` and
`rouser` directives:

```
createUser myuser SHA "my auth key" AES "my enc key"
rouser myuser
```

`snmpd` can be instructed to send `SNMPv2` traps to a remote `SNMP` trap receiver by adding the
following directive to the `snmpd.conf` configuration file:

```
trap2sink 192.0.2.1
```

The description of `dnsdist`'s `SNMP MIB` is available in `DNSDIST-MIB.txt`.

All functions and types
-----------------------
Within `dnsdist` several core object types exist:

 * Server: generated with newServer, represents a downstream server
 * ComboAddress: represents an IP address and port
 * DNSName: represents a domain name
 * NetmaskGroup: represents a group of netmasks
 * QPSLimiter: implements a QPS-based filter
 * SuffixMatchNode: represents a group of domain suffixes for rapid testing of membership
 * DNSHeader: represents the header of a DNS packet

The existence of most of these objects can mostly be ignored, unless you
plan to write your own hooks and policies, but it helps to understand an
expressions like:

```
> getServer(0).order=12         -- set order of server 0 to 12
> getServer(0):addPool("abuse") -- add this server to the abuse pool
```
The '.' means 'order' is a data member, while the ':' means addPool is a member function.

Here are all functions:

 * Practical
    * `shutdown()`: shut down `dnsdist`
    * quit or ^D: exit the console
    * `webserver(address:port, password [, apiKey [, customHeaders ]])`: launch a webserver with stats on that address with that password
    * `includeDirectory(dir)`: all files ending in `.conf` in the directory `dir` are loaded into the configuration. Starting with 1.2.0 they are loaded in a sorted manner. Sorting order is ascending and case sensitive.
    * `setAPIWritable(bool, [dir])`: allow modifications via the API. If `dir` is set, it must be a valid directory where the configuration files will be written by the API. Otherwise the modifications done via the API will not be written to the configuration and will not persist after a reload
 * ACL related:
    * `addACL(netmask)`: add to the ACL set who can use this server
    * `setACL({netmask, netmask})`: replace the ACL set with these netmasks. Use `setACL({})` to reset the list, meaning no one can use us
    * `showACL()`: show our ACL set
 * ClientState related:
    * function `showBinds()`: list every local bind
    * function `getBind(n)`: return the corresponding `ClientState` object
    * member `attachFilter(BPFFilter)`: attach a BPF Filter to this bind
    * member `detachFilter()`: detach the BPF Filter attached to this bind, if any
    * member `muted`: if set to true, UDP responses will not be sent for queries received on this bind. Default to false
    * member `toString()`: print the address this bind listens to
 * Network related:
    * `addLocal(addr, [, {doTCP=true, reusePort=false, tcpFastOpenSize=0, interface=\"\"}])`: add `addr` to the list of addresses we listen on. The second parameter is an optional table: `doTCP` sets TCP or not (UDP is always enabled), `reusePort` sets SO_REUSEPORT when available, `tcpFastOpenSize` sets the TCP Fast Open queue size, enabling TCP Fast Open when available and the value is larger than 0, `interface` sets the network interface to use
    * `setLocal(addr, [, {doTCP=true, reusePort=false, tcpFastOpenSize=0, interface=\"\"}])`: reset list of addresses we listen on to this address. The second parameter is the same optional table than the one described in `addLocal()`
 * Blocking related:
    * `addDomainBlock(domain)`: block queries within this domain
 * Carbon/Graphite/Metronome statistics related:
    * `carbonServer(serverIP, [ourname], [interval])`: report statistics to serverIP using our hostname, or 'ourname' if provided, every 'interval' seconds
 * Query counting related:
    * `clearQueryCounters()`: clears the query counter buffer.
    * `getQueryCounters([max])`: show current buffer of query counters, limited by `max` if provided.
    * `setQueryCount(bool)`: set whether queries should be counted.
    * `setQueryCountFilter(func)`: filter queries that would be counted, where `func` is a function with parameter `dq` which decides whether a query should and how it should be counted.
 * Control socket related:
    * `makeKey()`: generate a new server access key, emit configuration line ready for pasting
    * `setKey(key)`: set access key to that key.
    * `testCrypto()`: test of the crypto all works
    * `controlSocket(addr)`: open a control socket on this address / connect to this address in client mode
 * Diagnostics and statistics
    * `dumpStats()`: print all statistics we gather
    * `getStatisticsCounters()`: return the statistics counters as a Lua table
    * `grepq(Netmask|DNS Name|100ms [, n])`: shows the last n queries and responses matching the specified client address or range (Netmask), or the specified DNS Name, or slower than 100ms
    * `grepq({"::1", "powerdns.com", "100ms"} [, n])`: shows the last n queries and responses matching the specified client address AND range (Netmask) AND the specified DNS Name AND slower than 100ms
    * `topQueries(n[, labels])`: show top 'n' queries, as grouped when optionally cut down to 'labels' labels
    * `topResponses(n, kind[, labels])`: show top 'n' responses with RCODE=kind (0=NO Error, 2=ServFail, 3=ServFail), as grouped when optionally cut down to 'labels' labels
    * `topSlow([top][, limit][, labels])`: show `top` queries slower than `limit` milliseconds, grouped by last `labels` labels
    * `topBandwidth(top)`: show top-`top` clients that consume the most bandwidth over length of ringbuffer
    * `topClients(n)`: show top-`n` clients sending the most queries over length of ringbuffer
    * `setRingBuffersSize(n)`: set the capacity of the ringbuffers used for live traffic inspection to `n` (default to 10000)
    * `showResponseLatency()`: show a plot of the response time latency distribution
    * `showTCPStats()`: show some statistics regarding TCP
    * `showVersion()`: show the current version of dnsdist
 * Logging related
    * `infolog(string)`: log at level info
    * `warnlog(string)`: log at level warning
    * `errlog(string)`: log at level error
    * `setVerboseHealthChecks(bool)`: set whether health check errors will be logged
 * Server related:
    * `newServer("ip:port")`: instantiate a new downstream server with default settings
    * `newServer({address="ip:port", qps=1000, order=1, weight=10, pool="abuse", retries=5, tcpConnectTimeout=5, tcpSendTimeout=30, tcpRecvTimeout=30, tcpFastOpen=false, checkName="a.root-servers.net.", checkType="A", setCD=false, maxCheckFailures=1, mustResolve=false, useClientSubnet=true, source="address|interface name|address@interface"})`:
instantiate a server with additional parameters
    * `showServers()`: output all servers
    * `getServer(n)`: returns server with index n 
    * `getServers()`: returns a table with all defined servers
    * `rmServer(n)`: remove server with index n
    * `rmServer(server)`: remove this server object
 * Server member functions:
    * `addPool(pool)`: add this server to that pool
    * `getName()`: return the server name if any
    * `getNameWithAddr()`: return a string containing the server name if any plus the server address and port
    * `getOutstanding()`: this *returns* the number of outstanding queries (doesn't print it!)
    * `rmPool(pool)`: remove server from that pool
    * `setQPS(n)`: set the QPS setting to n
    * `setAuto()`: set this server to automatic availability testing
    * `setDown()`: force this server to be down
    * `setUp()`: force this server to be UP
    * `isUp()`: if this server is available
 * Server member data:
    * `upStatus`: if `dnsdist` considers this server available (overridden by `setDown()` and `setUp()`)
    * `name`: name of the server
    * `order`: order of this server in order-based server selection policies
    * `weight`: weight of this server in weighted server selection policies
 * Rule related:
    * `AllRule()`: matches all traffic
    * `AndRule()`: matches if all sub-rules matches
    * `DNSSECRule()`: matches queries with the DO flag set
    * `MaxQPSIPRule(qps, v4Mask=32, v6Mask=64)`: matches traffic exceeding the qps limit per subnet
    * `MaxQPSRule(qps)`: matches traffic **not** exceeding this qps limit
    * `NetmaskGroupRule(nmg, [src-bool])`: matches traffic from the specified network range. Pass `false` as second parameter to match NetmaskGroup  against destination address instead of source address
    * `NotRule()`: matches if the sub-rule does not match
    * `OrRule()`: matches if at least one of the sub-rules matches
    * `OpcodeRule()`: matches queries with the specified opcode
    * `QClassRule(qclass)`: matches queries with the specified qclass (numeric)
    * `QNameLabelsCountRule(min, max)`: matches if the qname has less than `min` or more than `max` labels
    * `QNameRule(qname)`: matches queries with the specified qname
    * `QNameWireLengthRule(min, max)`: matches if the qname's length on the wire is less than `min` or more than `max` bytes
    * `QTypeRule(qtype)`: matches queries with the specified qtype
    * `RCodeRule(rcode)`: matches queries or responses the specified rcode
    * `RDRule()`: matches queries with the `RD` flag set
    * `RegexRule(regex)`: matches the query name against the supplied regex
    * `RecordsCountRule(section, minCount, maxCount)`: matches if there is at least `minCount` and at most `maxCount` records in the `section` section
    * `RecordsTypeCountRule(section, type, minCount, maxCount)`: matches if there is at least `minCount` and at most `maxCount` records of type `type` in the `section` section
    * `RE2Rule(regex)`: matches the query name against the supplied regex using the RE2 engine
    * `SuffixMatchNodeRule(smn, [quiet-bool])`: matches based on a group of domain suffixes for rapid testing of membership. Pass `true` as second parameter to prevent listing of all domains matched.
    * `TCPRule(tcp)`: matches question received over TCP if `tcp` is true, over UDP otherwise
    * `TrailingDataRule()`: matches if the query has trailing data
 * Rule management related:
    * `clearRules()`: remove all current rules
    * `getAction(num)`: returns the Action associate with rule 'num'.
    * `mvCacheHitResponseRule(from, to)`: move cache hit response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule,
     in which case the rule will be moved to the last position.
    * `mvResponseRule(from, to)`: move response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule,
     in which case the rule will be moved to the last position.
    * `mvRule(from, to)`: move rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule,
     in which case the rule will be moved to the last position.
    * `newRuleAction(DNS Rule, DNS Action)`: return a pair of DNS Rule and DNS Action, to be used with `setRules()`
    * `rmCacheHitResponseRule(n)`: remove cache hit response rule n
    * `rmResponseRule(n)`: remove response rule n
    * `rmRule(n)`: remove rule n
    * `setRules(list)`: replace the current rules with the supplied list of pairs of DNS Rules and DNS Actions (see `newRuleAction()`)
    * `showCacheHitResponseRules()`: show all defined cache hit response rules
    * `showResponseRules()`: show all defined response rules
    * `showRules()`: show all defined rules
    * `topCacheHitResponseRule()`: move the last cache hit response rule to the first position
    * `topResponseRule()`: move the last response rule to the first position
    * `topRule()`: move the last rule to the first position
 * Built-in Actions for Rules:
    * `AllowAction()`: let these packets go through
    * `AllowResponseAction()`: let these packets go through
    * `DelayAction(milliseconds)`: delay the response by the specified amount of milliseconds (UDP-only)
    * `DelayResponseAction(milliseconds)`: delay the response by the specified amount of milliseconds (UDP-only)
    * `DisableECSAction()`: disable the sending of ECS to the backend
    * `DisableValidationAction()`: set the CD bit in the question, let it go through
    * `DropAction()`: drop these packets
    * `DropResponseAction()`: drop these packets
    * `ECSOverrideAction(bool)`: whether an existing ECS value should be overridden (true) or not (false)
    * `ECSPrefixLengthAction(v4, v6)`: set the ECS prefix length
    * `LogAction([filename], [binary], [append], [buffered])`: Log a line for each query, to the specified file if any, to the console (require verbose) otherwise. When logging to a file, the `binary` optional parameter specifies whether we log in binary form (default) or in textual form, the `append` optional parameter specifies whether we open the file for appending or truncate each time (default), and the `buffered` optional parameter specifies whether writes to the file are buffered (default) or not.
    * `MacAddrAction(option code)`: add the source MAC address to the query as EDNS0 option `option code`. This action is currently only supported on Linux
    * `NoRecurseAction()`: strip RD bit from the question, let it go through
    * `PoolAction(poolname)`: set the packet into the specified pool
    * `QPSPoolAction(maxqps, poolname)`: set the packet into the specified pool only if it **does not** exceed the specified QPS limits, letting the subsequent rules apply otherwise
    * `QPSAction(rule, maxqps)`: drop these packets if the QPS limits are exceeded
    * `RCodeAction(rcode)`: reply immediatly by turning the query into a response with the specified rcode
    * `RemoteLogAction(RemoteLogger [, alterFunction])`: send the content of this query to a remote logger via Protocol Buffer. `alterFunction` is a callback, receiving a DNSQuestion and a DNSDistProtoBufMessage, that can be used to modify the Protocol Buffer content, for example for anonymization purposes
    * `RemoteLogResponseAction(RemoteLogger [,alterFunction [,includeCNAME]])`: send the content of this response to a remote logger via Protocol Buffer. `alterFunction` is the same callback than the one in `RemoteLogAction` and `includeCNAME` indicates whether CNAME records inside the response should be parsed and exported. The default is to only exports A and AAAA records
    * `SkipCacheAction()`: don't lookup the cache for this query, don't store the answer
    * `SNMPTrapAction([reason])`: send an SNMP trap, adding the optional `reason` string as the query description
    * `SNMPTrapResponseAction([reason])`: send an SNMP trap, adding the optional `reason` string as the response description
    * `SpoofAction(ip[, ip])` or `SpoofAction({ip, ip, ..}): forge a response with the specified IPv4 (for an A query) or IPv6 (for an AAAA). If you specify multiple addresses, all that match the query type (A, AAAA or ANY) will get spoofed in
    * `SpoofCNAMEAction(cname)`: forge a response with the specified CNAME value
    * `TCAction()`: create answer to query with TC and RD bits set, to move to TCP
    * `TeeAction(remote[, addECS])`: send copy of query to remote, keep stats on responses. If `addECS` is set to `true`, EDNS Client Subnet information will be added to the query
 * Specialist rule generators
    * `addAnyTCRule()`: generate TC=1 answers to ANY queries received over UDP, moving them to TCP
    * `addDomainSpoof(domain, ip[, ip6])` or `addDomainSpoof(domain, {IP, IP, IP..})`: generate answers for A/AAAA/ANY queries using the ip parameters
    * `addDomainCNAMESpoof(domain, cname)`: generate CNAME answers for queries using the specified value
    * `addDisableValidationRule(domain)`: set the CD flags to 1 for all queries matching the specified domain
    * `addNoRecurseRule(domain)`: clear the RD flag for all queries matching the specified domain
    * `setDNSSECPool(pool)`: move queries requesting DNSSEC processing to this pool
 * Policy member data:
    * `name`: the policy name
    * `policy`: the policy function
 * Pool related:
    * `addPoolRule(domain, pool)`: send queries to this domain to that pool
    * `addPoolRule({domain, domain}, pool)`: send queries to these domains to that pool
    * `addPoolRule(netmask, pool)`: send queries from this netmask to that pool
    * `addPoolRule({netmask, netmask}, pool)`: send queries from these netmasks to that pool
    * `addQPSPoolRule(x, limit, pool)`: like `addPoolRule`, but only select at most 'limit' queries/s for this pool, letting the subsequent rules apply otherwise
    * `getPool(poolname)`: return the ServerPool named `poolname`
    * `getPoolServers(pool)`: return servers part of this pool
    * `showPools()`: list the current server pools
 * Lua Action related:
    * `addLuaAction(x, func)`: where 'x' is all the combinations from `addPoolRule`, and func is a 
      function with the parameter `dq`, which returns an action to be taken on this packet.
    * `addLuaResponseAction(x, func)`: where 'x' is all the combinations from `addPoolRule`, and func is a
      function with the parameter `dr`, which returns an action to be taken on this response packet.
      Good for rare packets but where you want to do a lot of processing.
 * Server selection policy related:
    * `setWHashedPertubation(value)`: set the hash perturbation value to be used in the `whashed` policy instead of a random one, allowing to have consistent `whashed` results on different instances
    * `setServerPolicy(policy)`: set server selection policy to that policy
    * `setServerPolicyLua(name, function)`: set server selection policy to one named 'name' and provided by 'function'
    * `showServerPolicy()`: show name of currently operational server selection policy
    * `newServerPolicy(name, function)`: create a policy object from a Lua function
    * `setServFailWhenNoServer(bool)`: if set, return a ServFail when no servers are available, instead of the default behaviour of dropping the query
    * `setPoolServerPolicy(policy, pool)`: set the server selection policy for this pool to that policy
    * `setPoolServerPolicyLua(name, function, poool)`: set the server selection policy for this pool to one named 'name' and provided by 'function'
    * `showPoolServerPolicy()`: show server selection policy for this pool
 * Available policies:
    * `firstAvailable`: Pick first server that has not exceeded its QPS limit, ordered by the server 'order' parameter
    * `whashed`: Weighted hashed ('sticky') distribution over available servers, based on the server 'weight' parameter
    * `wrandom`: Weighted random over available servers, based on the server 'weight' parameter
    * `roundrobin`: Simple round robin over available servers
    * `leastOutstanding`: Send traffic to downstream server with least outstanding queries, with the lowest 'order', and within that the lowest recent latency
 * Shaping related:
    * `addQPSLimit(domain, n)`: limit queries within that domain to n per second
    * `addQPSLimit({domain, domain}, n)`: limit queries within those domains (together) to n per second
    * `addQPSLimit(netmask, n)`: limit queries within that netmask to n per second
    * `addQPSLimit({netmask, netmask}, n)`: limit queries within those netmasks (together) to n per second   
 * Delaying related:
    * `addDelay(domain, n)`: delay answers within that domain by n milliseconds
    * `addDelay({domain, domain}, n)`: delay answers within those domains (together) by n milliseconds
    * `addDelay(netmask, n)`: delay answers within that netmask by n milliseconds
    * `addDelay({netmask, netmask}, n)`: delay answers within those netmasks (together) by n milliseconds
 * Answer changing functions:
    * `truncateTC(bool)`: if set (defaults to no starting with dnsdist 1.2.0) truncate TC=1 answers so they are actually empty. Fixes an issue for PowerDNS Authoritative Server 2.9.22. Note: turning this on breaks compatibility with RFC 6891.
    * `fixupCase(bool)`: if set (default to no), rewrite the first qname of the question part of the answer to match the one from the query. It is only useful when you have a downstream server that messes up the case of the question qname in the answer
 * Dynamic Block related:
    * `maintenance()`: called every second by dnsdist if defined, call functions below from it
    * `clearDynBlocks()`: clear all dynamic blocks
    * `showDynBlocks()`: show dynamic blocks in force
    * `addDynBlocks(addresses, message[, seconds[, action]])`: block the set of addresses with message `msg`, for `seconds` seconds (10 by default), applying `action` (default to the one set with `setDynBlocksAction()`)
    * `setDynBlocksAction(DNSAction)`: set which action is performed when a query is blocked. Only DNSAction.Drop (the default) and DNSAction.Refused are supported
    * `addBPFFilterDynBlocks(addresses, DynBPFFilter[, seconds])`: block the set of addresses using the supplied BPF Filter, for `seconds` seconds (10 by default)
    * `exceedServFails(rate, seconds)`: get set of addresses that exceed `rate` servfails/s over `seconds` seconds
    * `exceedNXDOMAINs(rate, seconds)`: get set of addresses that exceed `rate` NXDOMAIN/s over `seconds` seconds
    * `exceedRespByterate(rate, seconds)`: get set of addresses that exceeded `rate` bytes/s answers over `seconds` seconds
    * `exceedQRate(rate, seconds)`: get set of address that exceed `rate` queries/s over `seconds` seconds
    * `exceedQTypeRate(type, rate, seconds)`: get set of address that exceed `rate` queries/s for queries of type `type` over `seconds` seconds
 * ServerPool related:
    * `getCache()`: return the current packet cache, if any
    * `setCache(PacketCache)`: set the cache for this pool
    * `unsetCache()`: remove the packet cache from this pool
 * PacketCache related:
    * `expunge(n)`: remove entries from the cache, leaving at most `n` entries
    * `expungeByName(DNSName [, qtype=ANY, suffixMatch=false])`: remove entries matching the supplied DNSName and type from the cache. If suffixMatch is specified also removes names below DNSName
    * `isFull()`: return true if the cache has reached the maximum number of entries
    * `newPacketCache(maxEntries[, maxTTL=86400, minTTL=0, temporaryFailureTTL=60, staleTTL=60, dontAge=false])`: return a new PacketCache
    * `printStats()`: print the cache stats (hits, misses, deferred lookups and deferred inserts)
    * `purgeExpired(n)`: remove expired entries from the cache until there is at most `n` entries remaining in the cache
    * `toString()`: return the number of entries in the Packet Cache, and the maximum number of entries
 * Advanced functions for writing your own policies and hooks
    * ComboAddress related:
        * `newCA(address)`: return a new ComboAddress
        * `getPort()`: return the port number
        * `isIPv4()`: return true if the address is an IPv4, false otherwise
        * `isIPv6()`: return true if the address is an IPv6, false otherwise
        * `isMappedIPv4()`: return true if the address is an IPv4 mapped into an IPv6, false otherwise
        * `mapToIPv4()`: convert an IPv4 address mapped in a v6 one into an IPv4
        * `tostring()`: return in human-friendly format
        * `toString()`: alias for `tostring()`
        * `tostringWithPort()`: return in human-friendly format, with port number
        * `toStringWithPort()`: alias for `tostringWithPort()`
        * `truncate(bits)`: truncate the address to the specified number of bits
    * DNSName related:
        * `newDNSName(name)`: make a DNSName based on this .-terminated name
        * member `chopOff()`: remove left-most label and return true, or false if there are no labels
        * member `countLabels()`: return the number of labels
        * member `isPartOf(dnsname)`: is this dnsname part of that dnsname
        * member `tostring()`: return as a human friendly . terminated string
        * member `toString()`: alias for `tostring()`
        * member `wirelength()`: return the length on the wire
    * DNSQuestion related:
        * member `dh`: DNSHeader
        * member `ecsOverride`: whether an existing ECS value should be overridden (settable)
        * member `ecsPrefixLength`: the ECS prefix length to use (settable)
        * member `getDO()`: return true if the DNSSEC OK (DO) bit is set
        * member `len`: the question length
        * member `localaddr`: ComboAddress of the local bind this question was received on
        * member `opcode`: the question opcode
        * member `qname`: DNSName of this question
        * member `qclass`: QClass (as an unsigned integer) of this question
        * member `qtype`: QType (as an unsigned integer) of this question
        * member `remoteaddr`: ComboAddress of the remote client
        * member `rcode`: RCode of this question
        * member `sendTrap([reason])`: send a trap containing the description of the query, and the optional `reason` string
        * member `size`: the total size of the buffer starting at `dh`
        * member `skipCache`: whether to skip cache lookup / storing the answer for this question (settable)
        * member `tcp`: whether this question was received over a TCP socket
        * member `useECS`: whether to send ECS to the backend (settable)
    * DNSResponse gets the same member than DNSQuestion, plus some:
        * member `editTTLs(func)`: the function `func` is invoked for every entries in the answer, authority
        and additional section taking the section number (1 for answer, 2 for authority, 3 for additional),
        the qclass and qtype values and the current TTL, and returning the new TTL or 0 to leave it unchanged
    * DNSHeader related
        * member `getRD()`: get recursion desired flag
        * member `setRD(bool)`: set recursion desired flag
        * member `setTC(bool)`: set truncation flag (TC)
        * member `setQR(bool)`: set Query Response flag (setQR(true) indicates an *answer* packet)
        * member `getCD()`: get checking disabled flag
        * member `setCD(bool)`: set checking disabled flag
    * NetmaskGroup related
        * function `newNMG()`: returns a NetmaskGroup
        * member `addMask(mask)`: adds `mask` to the NetmaskGroup. Prefix with `!` to exclude this mask from matching.
        * member `addMasks(table)`: adds the keys of `table` to the NetmaskGroup. `table` should be a table whose keys
        are `ComboAddress` objects and values are integers, as returned by `exceed*` functions
        * member `match(ComboAddress)`: checks if ComboAddress is matched by this NetmaskGroup
        * member `clear()`: clears the NetmaskGroup
        * member `size()`: returns number of netmasks in this NetmaskGroup
    * QPSLimiter related:
        * `newQPSLimiter(rate, burst)`: configure a QPS limiter with that rate and that burst capacity
        * member `check()`: check if this QPSLimiter has a token for us. If yes, you must use it.
    * SuffixMatchNode related:
        * `newSuffixMatchNode()`: returns a new SuffixMatchNode
        * member `check(DNSName)`: returns true if DNSName is matched by this group
        * member `add(DNSName)`: add this DNSName to the node
 * Tuning related:
    * `setMaxTCPClientThreads(n)`: set the maximum of TCP client threads, handling TCP connections
    * `setMaxTCPConnectionDuration(n)`: set the maximum duration of an incoming TCP connection, in seconds. 0 (the default) means unlimited
    * `setMaxTCPConnectionsPerClient(n)`: set the maximum number of TCP connections per client. 0 (the default) means unlimited
    * `setMaxTCPQueriesPerConnection(n)`: set the maximum number of queries in an incoming TCP connection. 0 (the default) means unlimited
    * `setMaxTCPQueuedConnections(n)`: set the maximum number of TCP connections queued (waiting to be picked up by a client thread), defaults to 1000. 0 means unlimited
    * `setMaxUDPOutstanding(n)`: set the maximum number of outstanding UDP queries to a given backend server. This can only be set at configuration time and defaults to 10240
    * `setCacheCleaningDelay(n)`: set the interval in seconds between two runs of the cache cleaning algorithm, removing expired entries
    * `setCacheCleaningPercentage(n)`: set the percentage of the cache that the cache cleaning algorithm will try to free by removing expired entries. By default (100), all expired entries are removed
    * `setStaleCacheEntriesTTL(n)`: allows using cache entries expired for at most `n` seconds when no backend available to answer for a query
    * `setTCPDownstreamCleanupInterval(interval)`: minimum interval in seconds between two cleanups of the idle TCP downstream connections. Defaults to 60s
    * `setTCPUseSinglePipe(bool)`: whether the incoming TCP connections should be put into a single queue instead of using per-thread queues. Defaults to false
    * `setTCPRecvTimeout(n)`: set the read timeout on TCP connections from the client, in seconds
    * `setTCPSendTimeout(n)`: set the write timeout on TCP connections from the client, in seconds
    * `setUDPTimeout(n)`: set the maximum time dnsdist will wait for a response from a backend over UDP, in seconds. Defaults to 2
 * DNSCrypt related:
    * `addDNSCryptBind("127.0.0.1:8443", "provider name", "/path/to/resolver.cert", "/path/to/resolver.key", [, {doTCP=true, reusePort=false, tcpFastOpenSize=0, interface=\"\"}]):` listen to incoming DNSCrypt queries on 127.0.0.1 port 8443, with a provider name of "provider name", using a resolver certificate and associated key stored respectively in the `resolver.cert` and `resolver.key` files. The fifth parameter is the same optional table than the one described in `addLocal()`, except that TCP is always enabled
    * `generateDNSCryptProviderKeys("/path/to/providerPublic.key", "/path/to/providerPrivate.key"):` generate a new provider keypair
    * `generateDNSCryptCertificate("/path/to/providerPrivate.key", "/path/to/resolver.cert", "/path/to/resolver.key", serial, validFrom, validUntil):` generate a new resolver private key and related certificate, valid from the `validFrom` UNIX timestamp until the `validUntil` one, signed with the provider private key
    * `printDNSCryptProviderFingerprint("/path/to/providerPublic.key")`: display the fingerprint of the provided resolver public key
    * `showDNSCryptBinds():`: display the currently configured DNSCrypt binds
 * BPFFilter related:
    * function `newBPFFilter(maxV4, maxV6, maxQNames)`: return a new eBPF socket filter with a maximum of maxV4 IPv4, maxV6 IPv6 and maxQNames qname entries in the block tables
    * function `setDefaultBPFFilter(BPFFilter)`: when used at configuration time, the corresponding BPFFilter will be attached to every bind
    * member `attachToAllBinds()`: attach this filter to every bind already defined. This is the run-time equivalent of `setDefaultBPFFilter(bpf)`
    * member `block(ComboAddress)`: block this address
    * member `blockQName(DNSName [, qtype=255])`: block queries for this exact qname. An optional qtype can be used, default to 255
    * member `getStats()`: print the block tables
    * member `unblock(ComboAddress)`: unblock this address
    * member `unblockQName(DNSName [, qtype=255])`: remove this qname from the block list
 * DNSDistProtoBufMessage related:
    * member `setBytes(bytes)`: set the size of the query
    * member `setEDNSSubnet(Netmask)`: set the EDNS Subnet
    * member `setQueryTime(sec, usec)`: in a response message, set the time at which the query has been received
    * member `setQuestion(DNSName, qtype, qclass)`: set the question
    * member `setRequestor(ComboAddress)`: set the requestor
    * member `setRequestorFromString(string)`: set the requestor
    * member `setResponder(ComboAddress)`: set the responder
    * member `setResponderFromString(string)`: set the responder
    * member `setResponseCode(rcode)`: set the response code
    * member `setTime(sec, usec)`: set the time at which the query or response has been received
    * member `toDebugString()`: return an string containing the content of the message
 * DynBPFFilter related:
    * function `newDynBPFFilter(BPFFilter)`: return a new DynBPFFilter object using this BPF Filter
    * member `block(ComboAddress[, seconds]): add this address to the underlying BPF Filter for `seconds` seconds (default to 10 seconds)
    * member `purgeExpired()`: remove expired entries
    * function `registerDynBPFFilter(DynBPFFilter)`: register this dynamic BPF filter into the web interface so that its counters are displayed
    * function `unregisterDynBPFFilter(DynBPFFilter)`: unregister this dynamic BPF filter
 * RemoteLogger related:
    * `newRemoteLogger(address:port [, timeout=2, maxQueuedEntries=100, reconnectWaitTime=1])`: create a Remote Logger object, to use with `RemoteLogAction()` and `RemoteLogResponseAction()`
 * SNMP related:
    * `snmpAgent(enableTraps [, masterSocket])`: enable `SNMP` support. `enableTraps` is a boolean indicating whether traps should be sent and `masterSocket` an optional string specifying how to connect to the master agent
    * `sendCustomTrap(str)`: send a custom `SNMP` trap from Lua, containing the `str` string

All hooks
---------
`dnsdist` can call Lua per packet if so configured, and will do so with the following hooks:

  * `bool blockFilter(dq)`: if defined, called for every packet. If this
    returns true, the packet is dropped. If false is returned, `dnsdist` will check if the DNSHeader indicates
    the packet is now a query response. If so, `dnsdist` will answer the client directly with the modified packet.
  * `server policy(candidates, DNSQuestion)`: if configured with `setServerPolicyLua()`
    gets called for every packet. Candidates is a table of potential servers to pick from, ComboAddress is the 
    address of the requestor, DNSName and qtype describe name and type of query. DNSHeader meanwhile is available for 
    your inspection.


  
