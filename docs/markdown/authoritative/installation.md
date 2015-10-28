# Installing PowerDNS
Installation of the PowerDNS Authoritative server on UNIX systems can be done in several ways:

  * Binary packages provided by your distribution
  * Using the statically linked binary packages provided on the [website](https://www.powerdns.com/downloads.html)
  * Compiling from source

Running PowerDNS on Microsoft Windows is unsupported from version 3.0 onward.

## Binary Packages
### Debian-based Systems
PowerDNS Authoritative Server is available through the [apt](https://packages.debian.org/pdns-server) system.

**Note**: In the current 'stable' (codenamed 'wheezy') version 3.1 is included, it is recommended you install version 3.3 from backports.

`# apt-get install pdns-server`

Debian splits the backends into [several different packages](https://packages.debian.org/pdns-backend), install the required backend as follows:

`# apt-get install pdns-backend-$backend`

Alternatively, a statically linked binary package is provided on the [powerdns.com](https://www.powerdns.com/downloads.html) website that can be downloaded and installed by issueing:

`# dpkg -i pdns-static_$version_$arch.deb`

### Redhat-based Systems
On RedHat based system there are 2 options to install PowerDNS, from [EPEL](https://fedoraproject.org/wiki/EPEL) or the [repository from Kees Monshouwer](https://www.monshouwer.eu/download/3rd_party/pdns-recursor/). Add either to your list of reposities and install PowerDNS by issueing:

`# yum install pdns`

The different backends can be installed using

`# yum install pdns-backend-$backend`


### FreeBSD
PowerDNS Authoritative Server is available through the [ports](http://www.freshports.org/dns/powerdns/) system:

For the package:

`# pkg install dns/powerdns`

To have your system build the port:
`cd /usr/ports/dns/powerdns/ && make install clean`

### Mac OS X
PowerDNS Authoritative Server is available through Homebrew:

`$ brew install pdns`

## From source
See the [Compiling PowerDNS](../appendix/compiling-powerdns.md) chapter

# Running PowerDNS
PDNS is normally controlled via a SysV-style init.d script, often located in `/etc/init.d` or `/etc/rc.d/init.d`. This script accepts the following commands:

* `monitor`: Monitor is a special way to view the daemon. It executes PDNS in the foreground with a lot of logging turned on, which helps in determining startup problems. Besides running in the foreground, the raw PDNS control socket is made available. All external communication with the daemon is normally sent over this socket. While useful, the control console is not an officially supported feature. Commands which work are: `QUIT`, [`SHOW *`](internals.md#show-variable), `SHOW varname`, [`RPING`](internals.md#rping).
* `start`: Start PDNS in the background. Launches the daemon but makes no special effort to determine success, as making database connections may take a while. Use `status` to query success. You can safely run `start` many times, it will not start additional PDNS instances.
* `restart`: Restarts PDNS if it was running, starts it otherwise.
* `status`: Query PDNS for status. This can be used to figure out if a launch was successful. The status found is prefixed by the PID of the main PDNS process.
* `stop`: Requests that PDNS stop. Again, does not confirm success. Success can be ascertained with the `status` command.
* `dump`: Dumps a lot of statistics of a running PDNS daemon. It is also possible to single out specific variable by using the `show` command.
* `show variable`: Show a single statistic, as present in the output of the `dump`.
* `mrtg`: Dump statistics in mrtg format. See the performance [monitoring](../common/logging.md#performance-monitoring) documentation.

# Basic setup: configuring database connectivity
This shows you how to configure the Generic MySQL backend. This backend
is called 'gmysql', and needs to be configured in `pdns.conf`.  Add the
following lines, adjusted for your local setup (specifically, you may not
want to use the 'root' user):

```
launch=gmysql
gmysql-host=127.0.0.1
gmysql-user=root
gmysql-dbname=pdns
gmysql-password=mysecretpassword
```

Remove any earlier [`launch`](settings.md#launch) statements. Also remove the **bind-example-zones** statement as the **bind** module is no longer launched.

**Warning**: Make sure that you can actually resolve the hostname of your database without accessing the database! It is advised to supply an IP address here to prevent chicken/egg problems!

Now start PowerDNS using the monitor command:

```
# /etc/init.d/pdns monitor
(...)
15:31:30 About to create 3 backend threads
15:31:30 [gMySQLbackend] Failed to connect to database: Error: Unknown database 'pdns'
15:31:30 [gMySQLbackend] Failed to connect to database: Error: Unknown database 'pdns'
15:31:30 [gMySQLbackend] Failed to connect to database: Error: Unknown database 'pdns'
```

This is as to be expected - we did not yet add anything to MySQL for PDNS to read from. At this point you may also see other errors which indicate that PDNS either could not find your MySQL server or was unable to connect to it. Fix these before proceeding.

General MySQL knowledge is assumed in this chapter, please do not interpret these commands as DBA advice!

## Example: configuring MySQL
Connect to MySQL as a user with sufficient privileges and issue the following commands:

``` 
!!include=../modules/gmysqlbackend/schema.mysql.sql
```

Now we have a database and an empty table. PDNS should now be able to launch in monitor mode and display no errors:

```
# /etc/init.d/pdns monitor
(...)
15:31:30 PowerDNS 1.99.0 (Mar 12 2002, 15:00:28) starting up
15:31:30 About to create 3 backend threads
15:39:55 [gMySQLbackend] MySQL connection succeeded
15:39:55 [gMySQLbackend] MySQL connection succeeded
15:39:55 [gMySQLbackend] MySQL connection succeeded
```

In a different shell, a sample query sent to the server should now return quickly without data:

```
$ dig +short www.example.com @127.0.0.1
$
```

**Warning**: When debugging DNS problems, don't use `host`. Please use `dig`  or `drill`.

And indeed, the control console now shows:

```
Mar 12 15:41:12 We're not authoritative for 'www.example.com', sending unauth normal response
```

Now we need to add some records to our database (in a separate shell):

```
# mysql pdnstest
mysql> INSERT INTO domains (name, type) values ('example.com', 'NATIVE');
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'example.com','localhost ahu@ds9a.nl 1','SOA',86400,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'example.com','dns-us1.powerdns.net','NS',86400,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'example.com','dns-eu1.powerdns.net','NS',86400,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'www.example.com','192.0.2.10','A',120,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'mail.example.com','192.0.2.12','A',120,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'localhost.example.com','127.0.0.1','A',120,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'example.com','mail.example.com','MX',120,25);
```

**Warning**: Host names and the MNAME of a [SOA](../types.md#soa) records are NEVER terminated with a '.' in PowerDNS storage! If a trailing '.' is present it will inevitably cause problems, problems that may be hard to debug.

If we now requery our database, `www.example.com` should be present:

```
$ dig +short www.example.com @127.0.0.1
192.0.2.10

$ dig +short example.com MX @127.0.0.1
25 mail.example.com
```

To confirm what happened, issue the command [`SHOW *`](internals.md#show-variable) to the control console:

```
% show *
corrupt-packets=0,latency=0,packetcache-hit=2,packetcache-miss=5,packetcache-size=0,
qsize-a=0,qsize-q=0,servfail-packets=0,tcp-answers=0,tcp-queries=0,
timedout-packets=0,udp-answers=7,udp-queries=7,
%
```

The actual numbers will vary somewhat. Now enter `QUIT` and start PDNS as a regular daemon, and check launch status:

```
# /etc/init.d/pdns start
pdns: started
# /etc/init.d/pdns status
pdns: 8239: Child running
# /etc/init.d/pdns dump
pdns: corrupt-packets=0,latency=0,packetcache-hit=0,packetcache-miss=0,
packetcache-size=0,qsize-a=0,qsize-q=0,servfail-packets=0,tcp-answers=0,
tcp-queries=0,timedout-packets=0,udp-answers=0,udp-queries=0,
```

You now have a working database driven nameserver! To convert other zones already present, use the [`zone2sql`](migration.md#zone2sql) tool.

## Common problems
Most problems involve PDNS not being able to connect to the database.

### Can't connect to local MySQL server through socket '/tmp/mysql.sock' (2)
Your MySQL installation is probably defaulting to another location for its socket. Can be resolved by figuring out this location (often `/var/run/mysqld.sock`), and specifying it in the configuration file with the [`gmysql-socket`](backend-generic-mypgsql.md#gmysql-socket) parameter.

Another solution is to not connect to the socket, but to 127.0.0.1, which can be achieved by specifying [`gmysql-host=127.0.0.1`](backend-generic-mypgsql.md#gmysql-host).

### Host 'x.y.z.w' is not allowed to connect to this MySQL server
These errors are generic MySQL errors. Solve them by trying to connect to your MySQL database with the MySQL console utility `mysql` with the parameters specified to PDNS. Consult the MySQL documentation.

## Typical Errors after Installing
At this point some things may have gone wrong. Typical errors include:

### binding to UDP socket: Address already in use
This means that another nameserver is listening on port 53 already. You can resolve this problem by determining if it is safe to shutdown the nameserver already present, and doing so. If uncertain, it is also possible to run PDNS on another port. To do so, add [`local-port=5300`](settings.md#local-port) to `pdns.conf`, and try again. This however implies that you can only test your nameserver as clients expect the nameserver to live on port 53.

### binding to UDP socket: Permission denied
You must be superuser in order to be able to bind to port 53. If this is not a possibility, it is also possible to run PDNS on another port. To do so, add [`local-port=5300`](settings.md#local-port) to `pdns.conf`, and try again. This however implies that you can only test your nameserver as clients expect the nameserver to live on port 53.

### Unable to launch, no backends configured for querying
PDNS did not find the `launch=bind` instruction in pdns.conf.

### Multiple IP addresses on your server, PDNS sending out answers on the wrong one, Massive amounts of 'recvfrom gave error, ignoring: Connection refused'
If you have multiple IP addresses on the internet on one machine, UNIX often sends out answers over another interface than which the packet came in on. In such cases, use [`local-address`](settings.md#local-address) to bind to specific IP addresses, which can be comma separated. The second error comes from remotes disregarding answers to questions it didn't ask to that IP address and sending back ICMP errors.
