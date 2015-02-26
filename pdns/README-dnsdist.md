dnsdist
-------

WARNING: `dnsdist` is still under HEAVY development, but we are giving it some
publicity in hopes of getting constructive feedback that will help us guide
our feature set.

Do NOT take this into production, but please DO let us know your thoughts!

`dnsdist` is a highly DNS-, DoS- and abuse-aware loadbalancer. Its goal in
life is to route traffic to the best server, delivering top performance
to legitimate users while shunting or blocking abusive traffic.

`dnsdist` is dynamic, in the sense that its configuration can be changed at
runtime, and that its statistics can be queried from a console-like
interface.

Here is a minimal configuration:

```
$ cat dnsdistconf.lua
newServer2 {address="2001:4860:4860::8888", qps=1}
newServer2 {address="2001:4860:4860::8844", qps=1} 
newServer2 {address="2620:0:ccc::2", qps=10}
newServer2 {address="2620:0:ccd::2", qps=10}
newServer("192.168.1.2")

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
> listServers()
#   Address                   State     Qps    Qlim    Queries   Drops Drate    Lat
0   [2001:4860:4860::8888]:53    up     0.0       1          1       0 0.0      0.1
1   [2001:4860:4860::8844]:53    up     0.0       1          0       0 0.0      0.0
2   [2620:0:ccc::2]:53           up     0.0      10          0       0 0.0      0.0
3   [2620:0:ccd::2]:53           up     0.0      10          0       0 0.0      0.0
4   192.168.1.2:53               up     0.0       0          0       0 0.0      0.0
All                                     0.0                  1       0             
```

Here we also see our configuration. 5 downstream servers have been configured, of
which the first 4 have a QPS limit (of 1, 1, 10 and 10 queries per second,
respectively). The final server has no limit, which we can easily test:

```
$ for a in {0..1000}; do dig powerdns.com @127.0.0.1 -p 5200 +noall > /dev/null; done
> listServers()
#   Address                   State     Qps    Qlim    Queries   Drops Drate    Lat
0   [2001:4860:4860::8888]:53    up     1.0       1          7       0 0.0      1.6
1   [2001:4860:4860::8844]:53    up     1.0       1          6       0 0.0      0.6
2   [2620:0:ccc::2]:53           up    10.3      10         64       0 0.0      2.4
3   [2620:0:ccd::2]:53           up    10.3      10         63       0 0.0      2.4
4   192.168.1.2:53               up   125.8       0        671       0 0.0      0.4
All                                   145.0                811       0             
```

Note that the first 4 servers were all limited to near their configured QPS,
and that our final server was taking up most of the traffic. No queries were
dropped, and all servers remain up.

To force a server down, try:

```
> getServer(0):setDown()
> listServers()
#   Address                   State     Qps    Qlim    Queries   Drops Drate    Lat
0   [2001:4860:4860::8888]:53  DOWN     0.0       1          8       0 0.0      1.7
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

Now for some cool stuff. Let's say we know we're getting a whole bunch of
traffic for a domain used in DoS attacks, for example 'sh43354.cn'. We can
do two things with this kind of traffic. Either we block it outright, like
this:

```
> addDomainBlock("sh43354.cn.")
```

Or we configure a server dedicated to receiving the nasty stuff:

```
> abuseServer(newServer("192.168.1.3"))
> abuseSMN("sh43353.cn.")
```

The wonderful thing about this last solution is that it can also be used for
things where a domain might possibly be legit, but it is still causing load
on the system and slowing down the internet for everyone. With such an abuse
server, 'bad traffic' still gets a chance of an answer, but without
impacting the rest of the world (too much).

We can similarly add clients to the abuse server:

```
> abuseNM("192.168.12.0/24")
> abuseNM("192.168.13.14")
```

More power
----------
More powerful things can be achieved by defining a function called
`blockFilter()` in the configuration file, which can decide to drop traffic
on any reason it wants.

The default load balancing policy is called 'firstAvailable', which means
the first server that has not exceeded its QPS limit gets the traffic.  If
you don't like this default policy, you can create your own, like this for
example:

```
counter=0
servers=getServers()
function luaroundrobin(remote, qname, qtype) 
	 counter=counter+1
	 return servers[1+(counter % #servers)]
end

setServerPolicy(luaroundrobin)
```

Incidentally, this is similar to setting: `setServerPolicy(roundrobin)`
which uses the C++ based roundrobin policy.

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

