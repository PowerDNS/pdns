In a production environment, you will want to be able to monitor PDNS performance. Furthermore, PDNS can perform a configurable amount of operational logging. This chapter also explains how to configure syslog for best results.

# Logging
This chapter assumes familiarity with syslog, the unix logging device. PDNS logs messages with different levels. The more urgent the message, the lower the 'priority'. By default, PDNS will only log messages with an urgency of 3 or lower, but this can be changed using the [loglevel](settings.md#loglevel) setting in the configuration file. Setting it to 0 will eliminate all logging, 9 will log everything.

By default, logging is performed under the 'DAEMON' facility which is shared with lots of other programs. If you regard nameserving as important, you may want to have it under a dedicated facility so PDNS can log to its own files, and not clutter generic files.

For this purpose, syslog knows about 'local' facilities, numbered from LOCAL0 to LOCAL7. To move PDNS logging to LOCAL0, add [`logging-facility`](settings.md#logging-facility)`=0` to your configuration.

Furthermore, you may want to have separate files for the differing priorities - preventing lower priority messages from obscuring important ones.

A sample syslog.conf might be:

```
local0.info                       -/var/log/pdns.info
local0.warn                       -/var/log/pdns.warn
local0.err                        /var/log/pdns.err
```

Where local0.err would store the really important messages. For performance and disk space reasons, it is advised to audit your `syslog.conf` for statements also logging PDNS activities. Many `syslog.conf`s have a '\*.\*' statement to /var/log/syslog, which you may want to remove.

For performance reasons, be especially certain that no large amounts of synchronous logging take place. Under Linux, this is indicated by file names not starting with a '-' - indicating a synchronous log, which hurts performance.

Be aware that syslog by default logs messages at the configured priority and higher! To log only info messages, use `local0.=info`

# Performance Monitoring
Both PowerDNS daemons generate ample metrics which can be used to monitor performance. These metrics can be polled using the rec\_control and pdns\_control commands, and they are also available via the http-based API. Finally, they can be pushed to a Carbon/Graphite server, either native carbon, or our own Metronome implementation.

## Webserver
To launch the internal webserver, add a [`webserver`](settings.md#webserver) statement to the `pdns.conf`. This will instruct the PDNS daemon to start a webserver on localhost at port 8081, without password protection. Only local users (on the same host) will be able to access the webserver by default. The webserver lists a lot of information about the PDNS process, including frequent queries, frequently failing queries, lists of remote hosts sending queries, hosts sending corrupt queries etc. The webserver does not allow remote management of the daemon. The following webserver related configuration items are available:

* `webserver`: If set to anything but 'no', a webserver is launched.
* `webserver-address`: Address to bind the webserver to. Defaults to 127.0.0.1, which implies that only the local computer is able to connect to the nameserver! To allow remote hosts to connect, change to 0.0.0.0 or the physical IP address of your nameserver.
* `webserver-password`: If set, viewers will have to enter this plaintext password in order to gain access to the statistics.
* `webserver-port`: Port to bind the webserver to.
* `webserver-print-arguments`: Whether or not the webserver should print the server arguments.

## Via init.d commands
As mentioned before, the init.d commands **dump**, **show** and **mrtg** fetch data from a running PDNS process. Especially **mrtg** is powerful - it outputs data in a format that is ready for processing by the MRTG graphing tool.

MRTG can make insightful graphics on the performance of your nameserver, enabling the operator to easily spot trends. MRTG can be found on <http://people.ee.ethz.ch/~oetiker/webtools/mrtg/mrtg.html>

A sample mrtg.conf:

```
Interval: 5
WorkDir: /var/www/mrtg
WriteExpires: yes
Options[_]: growright,nopercent
XSize[_]: 600

#---------------------------------------------------------------

Target[udp-queries]: `/etc/init.d/pdns mrtg udp-queries udp-answers`
Options[udp-queries]: growright,nopercent,perminute
MaxBytes[udp-queries]: 600000
AbsMax[udp-queries]: 600000
Title[udp-queries]: Queries per minute
PageTop[udp-queries]: <H2>Queries per minute</H2>
WithPeak[udp-queries]: ymwd
YLegend[udp-queries]: queries/minute
ShortLegend[udp-queries]: q/m
LegendI[udp-queries]: udp-questions
LegendO[udp-queries]: udp-answers


Target[perc-failed]: `/etc/init.d/pdns mrtg udp-queries udp-answers`
Options[perc-failed]: growright,dorelpercent,perminute
MaxBytes[perc-failed]: 600000
AbsMax[perc-failed]: 600000
Title[perc-failed]: Queries per minute, with percentage success
PageTop[perc-failed]: <H2>Queries per minute, with percentage success</H2>
WithPeak[perc-failed]: ymwd
YLegend[perc-failed]: queries/minute
ShortLegend[perc-failed]: q/m
LegendI[perc-failed]: udp-questions
LegendO[perc-failed]: udp-answers


Target[packetcache-rate]: `/etc/init.d/pdns mrtg packetcache-hit udp-queries`
Options[packetcache-rate]: growright,dorelpercent,perminute
Title[packetcache-rate]: packetcache hitrate
MaxBytes[packetcache-rate]: 600000
AbsMax[packetcache-rate]: 600000
PageTop[packetcache-rate]: <H2>packetcache hitrate</H2>
WithPeak[packetcache-rate]: ymwd
YLegend[packetcache-rate]: queries/minute
ShortLegend[packetcache-rate]: q/m
LegendO[packetcache-rate]: total
LegendI[packetcache-rate]: hit

Target[packetcache-missrate]: `/etc/init.d/pdns mrtg packetcache-miss udp-queries`
Options[packetcache-missrate]: growright,dorelpercent,perminute
Title[packetcache-missrate]: packetcache MISSrate
MaxBytes[packetcache-missrate]: 600000
AbsMax[packetcache-missrate]: 600000
PageTop[packetcache-missrate]: <H2>packetcache MISSrate</H2>
WithPeak[packetcache-missrate]: ymwd
YLegend[packetcache-missrate]: queries/minute
ShortLegend[packetcache-missrate]: q/m
LegendO[packetcache-missrate]: total
LegendI[packetcache-missrate]: MISS

Target[latency]: `/etc/init.d/pdns mrtg latency`
Options[latency]: growright,nopercent,gauge
MaxBytes[latency]: 600000
AbsMax[latency]: 600000
Title[latency]: Query/answer latency
PageTop[latency]: <H2>Query/answer latency</H2>
WithPeak[latency]: ymwd
YLegend[latency]: usec
ShortLegend[latency]: usec
LegendO[latency]: latency
LegendI[latency]: latency

Target[recursing]: `/etc/init.d/pdns mrtg recursing-questions recursing-answers`
Options[recursing]: growright,nopercent,gauge
MaxBytes[recursing]: 600000
AbsMax[recursing]: 600000
Title[recursing]: Recursive questions/answers
PageTop[recursing]: <H2>Recursing questions/answers</H2>
WithPeak[recursing]: ymwd
YLegend[recursing]: queries/minute
ShortLegend[recursing]: q/m
LegendO[recursing]: recursing-questions
LegendI[recursing]: recursing-answers
```

## Sending to Carbon/Graphite/Metronome
For carbon/graphite/metronome, we use the following namespace. Everything starts with 'pdns.', which is then followed by the local hostname. Thirdly, we add either 'auth' or 'recursor' to siginify the daemon generating the metrics. This is then rounded off with the actual name of the metric. As an example: 'pdns.ns1.recursor.questions'.

Care has been taken to make the sending of statistics as unobtrusive as possible, the daemons will not be hindered by an unreachable carbon server, timeouts or connection refused situations.

To benefit from our carbon/graphite support, either install Graphite, or use our own lightweight statistics daemon, Metronome, currently available on [GitHub](https://github.com/ahupowerdns/metronome/).

Secondly, set [`carbon-server`](settings.md#carbon-server), possibly [`carbon-interval`](settings.md#carbon-interval) and possibly [`carbon-ourname`](settings.md#carbon-ourname) in the configuration.

## Counters & variables
A number of counters and variables are set during PDNS Authoritative Server operation.

### Counters
* **corrupt-packets**: Number of corrupt packets received
* **latency**: Average number of microseconds a packet spends within PDNS
* **packetcache-hit**: Number of packets which were answered out of the cache
* **packetcache-miss**: Number of times a packet could not be answered out of the cache
* **packetcache-size**: Amount of packets in the packetcache
* **qsize-a**: Size of the queue before the transmitting socket.
* **qsize-q**: Number of packets waiting for database attention
* **servfail-packets**: Amount of packets that could not be answered due to database problems
* **tcp-answers**: Number of answers sent out over TCP
* **tcp-questions**: Number of questions received over TCP
* **timedout-questions**: Amount of packets that were dropped because they had to wait too long internally
* **udp-answers**: Number of answers sent out over UDP
* **udp-questions**: Number of questions received over UDP

### Ring buffers
Besides counters, PDNS also maintains the ringbuffers. A ringbuffer records events, each new event gets a place in the buffer until it is full. When full, earlier entries get overwritten, hence the name 'ring'.

By counting the entries in the buffer, statistics can be generated. These statistics can currently only be viewed using the webserver and are in fact not even collected without the webserver running.

The following ringbuffers are available:

* **logmessages**: All messages logged
* **noerror-queries**: Queries for existing records but for a type we don't have.
Queries for, say, the AAAA record of a domain, when only an A is available. Queries are listed in the following format: name/type. So an AAAA query for pdns.powerdns.com looks like pdns.powerdns.com/AAAA.
* **nxdomain-queries**: Queries for non-existing records within existing domains.
If PDNS knows it is authoritative over a domain, and it sees a question for a record in that domain that does not exist, it is able to send out an authoritative 'no such domain' message. Indicates that hosts are trying to connect to services really not in your zone.
* **udp-queries**: All UDP queries seen.
* **remotes**: Remote server IP addresses.
Number of hosts querying PDNS. Be aware that UDP is anonymous - person A can send queries that appear to be coming from person B.
* **remote-corrupts**: Remotes sending corrupt packets.
Hosts sending PDNS broken packets, possibly meant to disrupt service. Be aware that UDP is anonymous - person A can send queries that appear to be coming from person B.
* **remote-unauth**: Remotes querying domains for which we are not authoritative.
It may happen that there are misconfigured hosts on the internet which are configured to think that a PDNS installation is in fact a resolving nameserver. These hosts will not get useful answers from PDNS. This buffer lists hosts sending queries for domains which PDNS does not know about.
* **servfail-queries**: Queries that could not be answered due to backend errors.
For one reason or another, a backend may be unable to extract answers for a certain domain from its storage. This may be due to a corrupt database or to inconsistent data. When this happens, PDNS sends out a 'servfail' packet indicating that it was unable to answer the question. This buffer shows which queries have been causing servfails.
* **unauth-queries**: Queries for domains that we are not authoritative for.
If a domain is delegated to a PDNS instance, but the backend is not made aware of this fact, questions come in for which no answer is available, nor is the authority. Use this ringbuffer to spot such queries.
