dnsdist introduction
--------------------
`dnsdist` is a highly DNS-, DoS- and abuse-aware loadbalancer. Its goal in
life is to route traffic to the best server, delivering top performance
to legitimate users while shunting or blocking abusive traffic.

`dnsdist` is dynamic, in the sense that its configuration can be changed at
runtime, and that its statistics can be queried from a console-like
interface.

Concepts
--------
dnsdist receives packets in one or several addresses it listens on. These
addresses can of course be IPv4 or IPv6 (dnsdist internally does not know
the difference). If you listen on the magic 0.0.0.0 or :: interfaces,
dnsdist does the right thing to set the return address of queries. So feel
free to listen on the ANY addresses.

By default, the program listens on 127.0.0.1 (not ::1!), port 53.

Before packets are processed they have to pass the ACL, which helpfully
defaults to RFC1918 private IP space. This prevents us from easily becoming
an open DNS resolver.

To add to the ACL, use one or more lines like: `addACL("130.161.0.0/16")`.
To change the listen address, pass `-l 130.161.252.29` on the command line,
or use one or more `addLocal("130.161.252.29")` lines.

Packet actions
--------------
Each packet can be:

 * Dropped
 * Turned into an answer directly
 * Forwarded to a downstream server
 * Modified and forwarded to a downstream and be modified back

To add downstream servers, either include them on the command line, like
this:

```
# dnsdist -l 130.161.252.29 -a 130.161.0.0/16 8.8.8.8 208.67.222.222 2620:0:ccc::2 2620:0:ccd::2
```

Or add them to the configuration file like this:
```
setLocal("130.161.252.29:53")
setACL("130.161.0.0/16") 
newServer("8.8.8.8")
newServer("208.67.222.222")
newServer("2620:0:ccc::2")
newServer("2620:0:0ccd::2")
```

In the default environment, put this file in `/etc/dnsdist/dnsdist.conf` (or
`/usr/local/etc/`, dnsdist will tell you on startup), and start dnsdist. 

These two equivalent configurations give you sane load balancing using a
very sensible distribution policy. Many users will simply be done with this
configuration. It works as well for authoritative as for recursive servers.

By default it will run on the foreground, add `--daemon` to make it go into
the background. Our distribution native packages know how to stop/start
themselves using operating system services.

Console, statistics, webserver
------------------------------
To fully benefit from the statistics, metrics and dynamic control, first
generate an access key:

```
$ dnsdist
> makeKey()
setKey(...)
```

Then paste that `setKey()` line, next with the following, into your
dnsdist.conf file:

```
-- paste the setKey() line from above here!
controlSocket("127.0.0.1") -- for the console
webserver("127.0.0.1:8083", "geheim2") --  instant webserve
carbonServer("2001:888:2000:1d::2") -- send our statistics to PowerDNS
```

Now restart `dnsdist`. Three things have changed now:

1. You can login to a running `dnsdist` daemon with `dnsdist -c`
2. If you connect to http://127.0.0.1:8083 and enter the password, you get
live stats
3. Your metrics will be reported to the public PowerDNS Metronome server



