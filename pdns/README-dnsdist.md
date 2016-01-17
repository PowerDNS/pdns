dnsdist
-------
`dnsdist` is a highly DNS-, DoS- and abuse-aware loadbalancer. Its goal in
life is to route traffic to the best server, delivering top performance
to legitimate users while shunting or blocking abusive traffic.

`dnsdist` is dynamic, in the sense that its configuration can be changed at
runtime, and that its statistics can be queried from a console-like
interface.

WARNING: `dnsdist` is still under HEAVY development, but we are giving it some
publicity in hopes of getting constructive feedback that will help us guide
our feature set.

Do not quite yet take this into production, but please DO let us know your
thoughts!  Test packages and/or tarballs can be found on
http://xs.powerdns.com/dnsdist/ (but see 'Packaged' below for more links).

Compiling
---------
`dnsdist` depends on boost, Lua or luajit and a pretty recent C++
compiler (g++ 4.8 or higher, clang 3.5 or higher). It can optionally use libsodium
for encrypted communications with its client.

To compile on CentOS 6 / RHEL6, use this script to install a working compiler:

```
wget -O /etc/yum.repos.d/slc6-devtoolset.repo http://linuxsoft.cern.ch/cern/devtoolset/slc6-devtoolset.repo
yum install devtoolset-2
scl enable devtoolset-2 bash
./configure
make
```

On other recent platforms, installing a Lua and the system C++ compiler should be enough. 

Packaged
--------
We build packages for `dnsdist` on our [repositories](https://repo.powerdns.com). In addition
`dnsdist` has been packaged for FreeBSD and can be found on https://freshports.org/dns/dnsdist

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
which the first 4 have a QPS limit (of 1, 1, 10 and 10 queries per second,
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
would've meant that `dnsdist` itself had concluded the server was down.
Similarly, setUp() forces a server to be up, and setAuto() returns it to the
default availability-probing.

To change the QPS for a server:
```
> getServer(0):setQPS(1000)
```

By default, the availability of a downstream server is checked by regularly
sending an A query for "a.root-servers.net.". A different query type and target
can be specified by passing, respectively, the 'checkType' and 'checkName'
parameters to `newServer`. The default behavior is to consider any valid response
with a RCODE different from ServFail as valid. If the 'mustResolve' parameter
of `newServer` is set to true, a response will only be considered valid if
its RCODE differs from NXDomain, ServFail and Refused.

```
newServer({address="192.0.2.1", checkType="AAAA", checkName="a.root-servers.net.", mustResolve=true})
```

In order to provide the downstream server with the address of the real client,
or at least the one talking to `dnsdist`, the 'useClientSubnet' parameter can be used
when declaring a new server. This parameter indicates whether an EDNS Client Subnet option
should be added to the request. If the incoming request already contains an EDNS Client Subnet value,
it will not be overriden unless setECSOverride is set to true. The source prefix-length may be
configured with:
```
> setECSSourcePrefixV4(24)
> setECSSourcePrefixV6(56)
```

TCP timeouts
------------

By default, a 2 seconds timeout is enforced on the TCP connection from the client,
meaning that a connection will be closed if the query can't be read in less than 2s
or if the answer can't be sent in less than 2s. This can be configured with:
```
> setTCPRecvTimeout(5)
> setTCPSendTimeout(5)
```

The same kind of timeouts is enforced on the TCP connections to the downstream servers.
The default value of 30s can be modified by passing the `tcpRecvTimeout` and `tcpSendTimeout`
parameters to `newServer`:
```
newServer({address="192.0.2.1", tcpRecvTimeout=10, tcpSendTimeout=10})
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

Specifying the interface name is only supported on system having IP_PKTINFO.


Configuration management
------------------------
At startup, configuration is read from the command line and the
configuration file.  The config can also be inspected and changed from the
console.  Sadly, our architecture does not allow us to serialize the running
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
# Wed Dec 23 2015 15:15:35 CET
setACL("192.0.2.0/24")
> addACL("127.0.0.1/8")
> showACL()
192.0.2.0/24
127.0.0.1/8
> delta()
# Wed Dec 23 2015 15:15:35 CET
setACL("192.0.2.0/24")
# Wed Dec 23 2015 15:15:44 CET
addACL("127.0.0.1/8")
>
```


Webserver
---------
To visually interact with `dnsdist`, try adding:
```
webserver("127.0.0.1:8083", "supersecret")
```

to the configuration, and point your browser at http://127.0.0.1:8083 and
log in with any username, and that password. Enjoy!

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
on the system and slowing down the internet for everyone. With such an abuse
server, 'bad traffic' still gets a chance of an answer, but without
impacting the rest of the world (too much).

We can similarly add clients to the abuse server:

```
> addPoolRule({"192.168.12.0/24", "192.168.13.14"}, "abuse")
```

To define a pool that should receive a QPS-limited amount of traffic, do:

```
> addQPSPoolRule("com.", 10000, "gtld-cluster")
```


Both `addDomainBlock` and `addPoolRule` end up the list of Rules 
and Actions (for which see below).

Servers can be added or removed to pools with:
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
 * QType (QTypeRule)
 * RegexRule on query name
 * Packet requests DNSSEC processing
 * Query received over UDP or TCP

A special rule is `AndRule{rule1, rule2}`, which only matches if all of its subrules match.

Current actions are:
 * Drop (DropAction)
 * Route to a pool (PoolAction)
 * Return with TC=1 (truncated, ie, instruction to retry with TCP)
 * Force a ServFail, NotImp or Refused answer
 * Send out a crafted response (NXDOMAIN or "real" data)
 * Delay a response by n milliseconds (DelayAction)
 * Modify query to remove RD bit

Rules can be added via:
 * addAction(DNS rule, DNS Action)
 * addAnyTCRule()
 * addDelay(DNS rule, delay in milliseconds)
 * addDisableValidationRule(DNS rule)
 * addDomainBlock(domain)
 * addDomainSpoof(domain, IPv4[, IPv6])
 * addDomainCNAMESpoof(domain, CNAME)
 * addLuaAction(DNS rule, lua function)
 * addNoRecurseRule(DNS rule)
 * addPoolRule(DNS rule, destination pool)
 * addQPSLimit(DNS rule, qps limit)
 * addQPSPoolRule(DNS rule, qps limit, destination pool)

A DNS rule can be:
 * an AllRule
 * an AndRule
 * a MaxQPSIPRule
 * a MaxQPSRule
 * a NetmaskGroupRule
 * a QTypeRule
 * a RegexRule
 * a SuffixMatchNodeRule
 * a TCPRule

A convenience function `makeRule()` is supplied which will make a NetmaskGroupRule for you or a SuffixMatchNodeRule
depending on how you call it. `makeRule("0.0.0.0/0")` will for example match all IPv4 traffic, `makeRule{"be","nl","lu"}` will
match all Benelux DNS traffic.

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
TCP/IP, and in this way you can implement ANY-to-TCP even for downstream
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
clients to fall back to TCP/IP.

To turn this per IP or range limit into a global limit, use MaxQPSRule(5000) instead of MaxQPSIPRule.

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
 * DNSAction.Delay: delay the response for the specified milliseconds (UDP-only)
 * DNSAction.Drop: drop the query
 * DNSAction.HeaderModify: indicate that the query has been turned into a response
 * DNSAction.None: continue to the next rule
 * DNSAction.Nxdomain: return a response with a NXDomain rcode
 * DNSAction.Pool: use the specified pool to forward this query
 * DNSAction.Spoof: spoof the response using the supplied IPv4 (A), IPv6 (AAAA) or string (CNAME) value

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

Inspecting live traffic
-----------------------
This is still much in flux, but for now, try:

 * `grepq(Netmask|DNS Name|100ms [, n])`: shows the last n queries and responses matching the specified client address or range (Netmask), or the specified DNS Name, or slower than 100ms
 * `grepq({"::1", "powerdns.com", "100ms"} [, n])`: shows the last n queries and responses matching the specified client address AND range (Netmask) AND the specified DNS Name AND slower than 100ms
 * `topBandwidth(top)`: show top-`top` clients that consume the most bandwidth over length of ringbuffer
 * `topQueries(20)`: shows the top-20 queries
 * `topQueries(20,2)`: shows the top-20 two-level domain queries (so `topQueries(20,1)` only shows TLDs)
 * `topResponses(20, 2)`: top-20 servfail responses (use ,3 for NXDOMAIN)
 * `topSlow([top][, limit][, labels])`: show `top` queries slower than `limit` milliseconds, grouped by last `labels` labels

For example:
```
> grepq("127.0.0.1/24")
-11.9   127.0.0.1:52599                                 16127 nxdomain.powerdns.com.    A             RD    Question
-11.7   127.0.0.1:52599                                 16127 nxdomain.powerdns.com.    A     175.6    RD    Non-Existent domain
> grepq("powerdns.com")
-38.7   127.0.0.1:52599                                 16127 nxdomain.powerdns.com.    A             RD    Question
-38.6   127.0.0.1:52599                                 16127 nxdomain.powerdns.com.    A     175.6    RD    Non-Existent domain
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
inspected or edited using showRule(), rmRule(), topRule(), mvRule() etc.

Dynamic load balancing
----------------------
The default load balancing policy is called 'leastOutstanding', which means 
we pick the server with the least queries 'in the air' (and within those, the one with the lowest 'order', and within those, the one with the lowest latency). 

Another policy, 'firstAvailable', picks the first server that has not
exceeded its QPS limit gets the traffic.  

A further policy, 'wrandom' assigns queries randomly, but based on the
'weight' parameter passed to `newServer`. `whashed` is a similar weighted policy,
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

Split horizon
-------------

To implement a split horizon, try:

```
authServer=newServer({address="2001:888:2000:1d::2", pool="auth"})

function splitSetup(servers, dq)
	 if(dq.dh:getRD() == false)
	 then
		return leastOutstanding.policy(getPoolServers("auth"), dq)
	 else
		return leastOutstanding.policy(servers, dq)
	 end
end

setServerPolicyLua("splitsetup", splitSetup)
```

This will forward queries that don't want recursion to the pool of auth
servers, and will apply the default load balancing policy to all other
queries.

Dynamic Rule Generation
-----------------------
To set dynamic rules, based on recent traffic, define a function called `maintenance()` in Lua. It will
get called every second, and from this function you can set rules to block traffic based on statistics.

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
all functions below.


Running it for real
-------------------
First run on the command line, and generate a key:

```
# dnsdist
> makeKey()
setKey("sepuCcHcQnSAZgNbNPCCpDWbujZ5esZJmrt/wh6ldkQ=")
```

Now add this setKey line to `dnsdistconf.lua`, and also add:

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
The '.' means 'order' is a data member, while the ':' meand addPool is a member function.

Here are all functions:

 * Practical
   * `shutdown()`: shut down `dnsdist`
   * quit or ^D: exit the console
   * `webserver(address, password)`: launch a webserver with stats on that address with that password
 * ACL related:
   * `addACL(netmask)`: add to the ACL set who can use this server
   * `setACL({netmask, netmask})`: replace the ACL set with these netmasks. Use `setACL({})` to reset the list, meaning no one can use us
   * `showACL()`: show our ACL set
 * Network related:
   * `addLocal(netmask, [false])`: add to addresses we listen on. Second optional parameter sets TCP/IP or not.
   * `setLocal(netmask, [false])`: reset list of addresses we listen on to this address. Second optional parameter sets TCP/IP or not.
 * Blocking related:
   * `addDomainBlock(domain)`: block queries within this domain
 * Carbon/Graphite/Metronome statistics related:
   * `carbonServer(serverIP, [ourname], [interval])`: report statistics to serverIP using our hostname, or 'ourname' if provided, every 'interval' seconds
 * Control socket related:
   * `makeKey()`: generate a new server access key, emit configuration line ready for pasting
   * `setKey(key)`: set access key to that key. 
   * `testCrypto()`: test of the crypto all works
   * `controlSocket(addr)`: open a control socket on this address / connect to this address in client mode
 * Diagnostics and statistics
   * `dumpStats()`: print all statistics we gather
   * `grepq(Netmask|DNS Name|100ms [, n])`: shows the last n queries and responses matching the specified client address or range (Netmask), or the specified DNS Name, or slower than 100ms
   * `grepq({"::1", "powerdns.com", "100ms"} [, n])`: shows the last n queries and responses matching the specified client address AND range (Netmask) AND the specified DNS Name AND slower than 100ms
   * `topQueries(n[, labels])`: show top 'n' queries, as grouped when optionally cut down to 'labels' labels
   * `topResponses(n, kind[, labels])`: show top 'n' responses with RCODE=kind (0=NO Error, 2=ServFail, 3=ServFail), as grouped when optionally cut down to 'labels' labels
   * `topSlow([top][, limit][, labels])`: show `top` queries slower than `limit` milliseconds, grouped by last `labels` labels   
   * `topBandwidth(top)`: show top-`top` clients that consume the most bandwidth over length of ringbuffer
   * `showResponseLatency()`: show a plot of the response time latency distribution
 * Logging related
   * `infolog(string)`: log at level info
   * `warnlog(string)`: log at level warning
   * `errlog(string)`: log at level error
 * Server related:
   * `newServer("ip:port")`: instantiate a new downstream server with default settings
   * `newServer({address="ip:port", qps=1000, order=1, weight=10, pool="abuse", retries=5, tcpSendTimeout=30, tcpRecvTimeout=30, checkName="a.root-servers.net.", checkType="A", mustResolve=false, useClientSubnet=true, source="address|interface name|address@interface"})`:
instantiate a server with additional parameters
   * `showServers()`: output all servers
   * `getServer(n)`: returns server with index n 
   * `getServers()`: returns a table with all defined servers
   * `rmServer(n)`: remove server with index n
   * `rmServer(server)`: remove this server object
 * Server member functions:
   * `addPool(pool)`: add this server to that pool
   * `getOutstanding()`: this *returns* the number of outstanding queries (doesn't print it!)
   * `rmPool(pool)`: remove server from that pool
   * `setQPS(n)`: set the QPS setting to n
   * `setAuto()`: set this server to automatic availability testing
   * `setDown()`: force this server to be down
   * `setUp()`: force this server to be UP
   * `isUp()`: if this server is available
 * Server member data:
   * `upStatus`: if `dnsdist` considers this server available (overridden by `setDown()` and `setUp()`)
   * `order`: order of this server in order-based server selection policies
   * `weight`: weight of this server in weighted server selection policies
 * Rule related:
   * `AllRule()`: matches all traffic
   * `AndRule()`: matches if all sub-rules matches
   * `DNSSECRule()`: matches queries with the DO flag set
   * `MaxQPSIPRule(qps, v4Mask=32, v6Mask=64)`: matches traffic exceeding the qps limit per subnet
   * `MaxQPSRule(qps)`: matches traffic not exceeding this qps limit
   * `NetmaskGroupRule()`: matches traffic from the specified network range
   * `QTypeRule(qtype)`: matches queries with the specified qtype
   * `RegexRule(regex)`: matches the query name against the supplied regex
   * `SuffixMatchNodeRule()`: matches based on a group of domain suffixes for rapid testing of membership
   * `TCPRule(tcp)`: matches question received over TCP if `tcp` is true, over UDP otherwise
 * Rule management related:
   * `showRules()`: show all defined rules (Pool, Block, QPS, addAnyTCRule)
   * `rmRule(n)`: remove rule n
   * `mvRule(from, to)`: move rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule,
     in which case the rule will be moved to the last position.
   * `topRule()`: move the last rule to the first position
 * Built-in Actions for Rules:
   * `AllowAction()`: let these packets go through
   * `DelayAction()`: delay the response by the specified amount of milliseconds (UDP-only)
   * `DisableValidationAction()`: set the CD bit in the question, let it go through
   * `DropAction()`: drop these packets
   * `LogAction()`: Log a line for each query, to the specified file if any, to the console (require verbose) otherwise
   * `NoRecurseAction()`: strip RD bit from the question, let it go through
   * `PoolAction()`: set the packet into the specified pool
   * `QPSPoolAction()`: set the packet into the specified pool only if it does not exceed the specified QPS limits
   * `QPSAction()`: drop these packets if the QPS limits are exceeded
   * `RCodeAction()`: reply immediatly by turning the query into a response with the specified rcode
   * `SpoofAction()`: forge a response with the specified IPv4 (for an A query) or IPv6 (for an AAAA). If you specify two addresses, the first one should be an IPv4 and will be used for A, the second an IPv6 for an AAAA
   * `SpoofCNAMEAction()`: forge a response with the specified CNAME value
   * `TCAction()`: create answer to query with TC and RD bits set, to move to TCP/IP
 * Specialist rule generators
   * `addAnyTCRule()`: generate TC=1 answers to ANY queries received over UDP, moving them to TCP
   * `addDomainSpoof(domain, ip[, ip6])`: generate answers for A queries using the ip parameter (AAAA if ip is an IPv6). If ip6 is supplied, generate answers for AAAA queries too
   * `addDomainCNAMESpoof(domain, cname)`: generate CNAME answers for queries using the specified value
   * `addDisableValidationRule(domain)`: set the CD flags to 1 for all queries matching the specified domain
   * `addNoRecurseRule(domain)`: clear the RD flag for all queries matching the specified domain
   * `setDNSSECPool()`: move queries requesting DNSSEC processing to this pool
 * Policy member data:
   * `name`: the policy name
   * `policy`: the policy function
 * Pool related:
   * `addPoolRule(domain, pool)`: send queries to this domain to that pool
   * `addPoolRule({domain, domain}, pool)`: send queries to these domains to that pool
   * `addPoolRule(netmask, pool)`: send queries to this netmask to that pool
   * `addPoolRule({netmask, netmask}, pool)`: send queries to these netmasks to that pool  
   * `addQPSPoolRule(x, limit, pool)`: like `addPoolRule`, but only select at most 'limit' queries/s for this pool
   * `getPoolServers(pool)`: return servers part of this pool
 * Lua Action related:
   * `addLuaAction(x, func)`: where 'x' is all the combinations from `addPoolRule`, and func is a 
      function with parameters remote, qname, qtype, dh and len, which returns an action to be taken 
      on this packet. Good for rare packets but where you want to do a lot of processing.
 * Server selection policy related:
   * `setServerPolicy(policy)`: set server selection policy to that policy
   * `setServerPolicyLua(name, function)`: set server selection policy to one named 'name' and provided by 'function'
   * `showServerPolicy()`: show name of currently operational server selection policy
   * `newServerPolicy(name, function)`: create a policy object from a Lua function
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
   * `truncateTC(bool)`: if set (default) truncate TC=1 answers so they are actually empty. Fixes an issue for PowerDNS Authoritative Server 2.9.22.
   * `fixupCase(bool)`: if set (default to no), rewrite the first qname of the question part of the answer to match the one from the query. It is only useful when you have a downstream server that messes up the case of the question qname in the answer
 * Dynamic Block related:
   * `maintenance()`: called every second by dnsdist if defined, call functions below from it
   * `clearDynBlocks()`: clear all dynamic blocks
   * `showDynBlocks()`: show dynamic blocks in force
   * `addDynBlocks(addresses, message[, seconds])`: block the set of addresses with message `msg`, for `seconds` seconds (10 by default)
   * `exceedServFails(rate, seconds)`: get set of addresses that exceed `rate` servails/s over `seconds` seconds
   * `exceedNXDOMAINs(rate, seconds)`: get set of addresses that exceed `rate` NXDOMAIN/s over `seconds` seconds
   * `exceedRespByterate(rate, seconds)`: get set of addresses that exeeded `rate` bytes/s answers over `seconds` seconds
   * `exceedQRate(rate, seconds)`: get set of address that exceed `rate` queries/s over `seconds` seconds
   * `exceedQTypeRate(type, rate, seconds)`: get set of address that exceed `rate` queries/s for queries of type `type` over `seconds` seconds
 * Advanced functions for writing your own policies and hooks
   * ComboAddress related:
     * `newCA(address)`: return a new ComboAddress
     * `getPort()`: return the port number
     * `tostring()`: return in human-friendly format
     * `toString()`: alias for `tostring()`
     * `tostringWithPort()`: return in human-friendly format, with port number
     * `toStringWithPort()`: alias for `tostringWithPort()`
   * DNSName related:
     * `newDNSName(name)`: make a DNSName based on this .-terminated name
     * member `isPartOf(dnsname)`: is this dnsname part of that dnsname
     * member `tostring()`: return as a human friendly . terminated string
     * member `toString()`: alias for `tostring()`
   * DNSQuestion related:
     * member `dh`: DNSHeader
     * member `len`: the question length
     * member `localaddr`: ComboAddress of the local bind this question was received on
     * member `qname`: DNSName of this question
     * member `qtype`: QType (as an unsigned integer) of this question
     * member `remoteaddr`: ComboAddress of the remote client
     * member `rcode`: RCode of this question
     * member `size`: the total size of the buffer starting at `dh`
     * member `tcp`: whether this question was received over a TCP socket
   * DNSHeader related
     * member `getRD()`: get recursion desired flag
     * member `setRD(bool)`: set recursion desired flag
     * member `setTC(bool)`: set truncation flag (TC)
     * member `setQR(bool)`: set Query Response flag (setQR(true) indicates an *answer* packet)
     * member `getCD()`: get checking disabled flag
     * member `setCD(bool)`: set checking disabled flag
   * NetmaskGroup related
     * function `newNMG()`: returns a NetmaskGroup
     * member `addMask(mask)`: adds `mask` to the NetmaskGroup
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
   * `setTCPRecvTimeout(n)`: set the read timeout on TCP connections from the client, in seconds
   * `setTCPSendTimeout(n)`: set the write timeout on TCP connections from the client, in seconds
   * `setMaxTCPClientThreads(n)`: set the maximum of TCP client threads, handling TCP connections
   * `setMaxUDPOutstanding(n)`: set the maximum number of outstanding UDP queries to a given backend server. This can only be set at configuration time
 * DNSCrypt related:
   * `addDNSCryptBind("127.0.0.1:8443", "provider name", "/path/to/resolver.cert", "/path/to/resolver.key"):` listen to incoming DNSCrypt queries on 127.0.0.1 port 8443, with a provider name of "provider name", using a resolver certificate and associated key stored respectively in the `resolver.cert` and `resolver.key` files
   * `generateDNSCryptProviderKeys("/path/to/providerPublic.key", "/path/to/providerPrivate.key"):` generate a new provider keypair
   * `generateDNSCryptCertificate("/path/to/providerPrivate.key", "/path/to/resolver.cert", "/path/to/resolver.key", serial, validFrom, validUntil):` generate a new resolver private key and related certificate, valid from the `validFrom` timestamp until the `validUntil` one, signed with the provider private key
   * `printDNSCryptProviderFingerprint("/path/to/providerPublic.key")`: display the fingerprint of the provided resolver public key
   * `showDNSCryptBinds():`: display the currently configured DNSCrypt binds

All hooks
---------
`dnsdist` can call Lua per packet if so configured, and will do so with the following hooks:

  * `bool blockFilter(ComboAddress, DNSQuestion)`: if defined, called for every function. If this
    returns true, the packet is dropped. If false is returned, `dnsdist` will check if the DNSHeader indicates
    the packet is now a query response. If so, `dnsdist` will answer the client directly with the modified packet.
  * `server policy(candidates, DNSQuestion)`: if configured with `setServerPolicyLua()`
    gets called for every packet. Candidates is a table of potential servers to pick from, ComboAddress is the 
    address of the requestor, DNSName and qtype describe name and type of query. DNSHeader meanwhile is available for 
    your inspection.


  
