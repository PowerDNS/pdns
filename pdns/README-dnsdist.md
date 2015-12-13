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
compiler (g++ 4.8 or higher, clang 3.5). It can optionally use libsodium
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
We build packages for dnsdist on our [repositories](https://repo.powerdns.com). In addition
dnsdist has been packaged for FreeBSD and can be found on https://freshports.org/dns/dnsdist

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
newServer {address="2001:4860:4860::8888", qps=1}
newServer {address="2001:4860:4860::8844", qps=1} 
newServer {address="2620:0:ccc::2", qps=10}
newServer {address="2620:0:ccd::2", name="dns1", qps=10}
newServer("192.168.1.2")
setServerPolicy(firstAvailable) -- first server within its QPS limit

$ dnsdist --local=0.0.0.0:5200 --daemon=no
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

Note that dnsdist offered us a prompt above, and on it we can get some
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
would've meant that dnsdist itself had concluded the server was down.
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
newServer {address="192.0.2.1", checkType="AAAA", checkName="a.root-servers.net.", mustResolve=true}
```

In order to provide the downstream server with the address of the real client,
or at least the one talking to dnsdist, the 'useClientSubnet' parameter can be used
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
newServer {address="192.0.2.1", tcpRecvTimeout=10, tcpSendTimeout=10}
```

Webserver
---------
To visually interact with dnsdist, try adding:
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
> newServer{address="192.168.1.3", pool="abuse"}
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

A special rule is `AndRule{rule1, rule2}`, which only matches if all of its subrules match.

Current actions are:
 * Drop
 * Route to a pool
 * Return with TC=1 (truncated, ie, instruction to retry with TCP)
 * Force a ServFail, NotImp or Refused answer
 * Send out a crafted response (NXDOMAIN or "real" data)
 * Delay a response by n milliseconds
 * Modify query to remove RD bit

More power
----------
More powerful things can be achieved by defining a function called
`blockFilter()` in the configuration file, which can decide to drop traffic
on any reason it wants. If you return 'true' from there, the query will get
blocked.

A demo on how to do this and many other things can be found on
https://github.com/ahupowerdns/pdns/blob/dnsname/pdns/dnsdistconf.lua and 
the exact definition of `blockFilter()` is at the end of this document.

ANY or whatever to TC
---------------------
The `blockFilter()` also gets passed read/writable copy of the DNS Header.
If you invoke setQR(1) on that, dnsdist knows you turned the packet into
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

To turn this per IP or range limit into a global limt, use MaxQPSRule(5000) instead of MaxQPSIPRule.

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
function luarule(remote, qname, qtype, dh, len)
        if(qtype==35) -- NAPTR
        then
                return DNSAction.Pool, "abuse" -- send to abuse pool
        else
                return DNSAction.None, ""      -- no action
        end
end
```

DNSSEC
------
To provide DNSSEC service from a separate pool, try:
```
newServer{address="2001:888:2000:1d::2", pool="dnssec"}
newServer{address="2a01:4f8:110:4389::2", pool="dnssec"}
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

 * `topQueries(20)`: shows the top-20 queries
 * `topQueries(20,2)`: shows the top-20 two-level domain queries (so `topQueries(20,1)` only shows TLDs)
 * `topResponses(20, 2)`: top-20 servfail responses (use ,3 for NXDOMAIN)


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
function luaroundrobin(servers, remote, qname, qtype, dh) 
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
authServer=newServer{address="2001:888:2000:1d::2", pool="auth"}

function splitSetup(servers, remote, qname, qtype, dh)
	 if(dh:getRD() == false)
	 then
		return leastOutstanding.policy(getPoolServers("auth"), remote, qname, qtype, dh)
	 else
		return leastOutstanding.policy(servers, remote, qname, qtype, dh)
	 end
end

setServerPolicyLua("splitsetup", splitSetup)
```

This will forward queries that don't want recursion to the pool of auth
servers, and will apply the default load balancing policy to all other
queries.

Running it for real
-------------------
First run on the command line, and generate a key:

```
# dnsdist --daemon-no
> makeKey()
setKey("sepuCcHcQnSAZgNbNPCCpDWbujZ5esZJmrt/wh6ldkQ=")
```
Now add this setKey line to `dnsdistconf.lua`, and also add:

```
controlSocket("0.0.0.0") -- or add portnumber too
```

Then start `dnsdist` as a daemon, and then connect to it:
```
# dnsdist
# dnsdist --client
> 
```

Please note that, without libsodium support, 'makeKey()' will return
setKey("plaintext") and the communication between the client and the
server will not be encrypted.

ACL, who can use dnsdist
------------------------
For safety reasons, by default only private networks can use dnsdist, see below
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
graphs for dnsdist by default.

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
   * `shutdown()`: shut down dnsdist
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
   * `topQueries(n[, labels])`: show top 'n' queries, as grouped when optionally cut down to 'labels' labels
   * `topResponses(n, kind[, labels])`: show top 'n' responses with RCODE=kind (0=NO Error, 2=ServFail, 3=ServFail), as grouped when optionally cut down to 'labels' labels
   * `showResponseLatency()`: show a plot of the response time latency distribution
 * Logging related
   * `infolog(string)`: log at level info
   * `warnlog(string)`: log at level warning
   * `errlog(string)`: log at level error
 * Server related:
   * `newServer("ip:port")`: instantiate a new downstream server with default settings
   * `newServer({address="ip:port", qps=1000, order=1, weight=10, pool="abuse", retries=5, tcpSendTimeout=30, tcpRecvTimeout=30, checkName="a.root-servers.net.", checkType="A", mustResolve=false, useClientSubnet=true})`:
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
   * `upStatus`: if dnsdist considers this server available (overridden by `setDown()` and `setUp()`)
   * `order`: order of this server in order-based server selection policies
   * `weight`: weight of this server in weighted server selection policies
 * Rule related:
   * `showRules()`: show all defined rules (Pool, Block, QPS, addAnyTCRule)
   * `rmRule(n)`: remove rule n
   * `mvRule(from, to)`: move rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule,
     in which case the rule will be moved to the last position.
 * Built-in Actions for Rules:
   * `AllowAction()`: let these packets go through
   * `DropAction()`: drop these packets
   * `NoRecurseAction()`: strip RD bit from the question, let it go through
   * `TCAction()`: create answer to query with TC and RD bits set, to move to TCP/IP
   * `DisableValidationAction()`: set the CD bit in the question, let it go through
 * Specialist rule generators
   * addAnyTCRule(): generate TC=1 answers to ANY queries, moving them to TCP
   * setDNSSECPool(): move queries requesting DNSSEC processing to this pool
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
 * Advanced functions for writing your own policies and hooks
   * ComboAddress related:
     * `tostring()`: return in human-friendly format
   * DNSName related:
     * `newDNSName(name)`: make a DNSName based on this .-terminated name
     * member `isPartOf(dnsname)`: is this dnsname part of that dnsname
     * member `tostring()`: return as a human friendly . terminated string
   * DNSHeader related
     * member `getRD()`: get recursion desired flag
     * member `setRD(bool)`: set recursion desired flag
     * member `setTC(bool)`: set truncation flag (TC)
     * member `setQR(bool)`: set Query Response flag (setQR(true) indicates an *answer* packet)
     * member `getCD()`: get checking disabled flag
     * member `setCD(bool)`: set checking disabled flag
   * NetmaskGroup related
     * nothing yet
   * QPSLimiter related:
     * `newQPSLimiter(rate, burst)`: configure a QPS limiter with that rate and that burst capacity
     * member `check()`: check if this QPSLimiter has a token for us. If yes, you must use it.
   * SuffixMatchNode related:
     * newSuffixMatchNode(): returns a new SuffixMatchNode
     * member `check(DNSName)`: returns true if DNSName is matched by this group
     * member `add(DNSName)`: add this DNSName to the node
 * Tuning related:
   * setTCPRecvTimeout(n): set the read timeout on TCP connections from the client, in seconds.
   * setTCPSendTimeout(n): set the write timeout on TCP connections from the client, in seconds.
   * setMaxTCPClientThreads(n): set the maximum of TCP client threads, handling TCP connections.
   * setMaxUDPOutstanding(n): set the maximum number of outstanding UDP queries to a given backend server. This can only be set at configuration time.

All hooks
---------
`dnsdist` can call Lua per packet if so configured, and will do so with the following hooks:

  * `bool blockfilter(ComboAddress, DNSName, qtype, DNSHeader)`: if defined, called for every function. If this
    returns true, the packet is dropped. If false is returned, `dnsdist` will check if the DNSHeader indicates
    the packet is now a query response. If so, `dnsdist` will answer the client directly with the modified packet.
  * `server policy(candidates, ComboAddress, DNSName, qtype, DNSHeader)`: if configured with `setServerPolicyLua()` 
    gets called for every packet. Candidates is a table of potential servers to pick from, ComboAddress is the 
    address of the requestor, DNSName and qtype describe name and type of query. DNSHeader meanwhile is available for 
    your inspection.


  
