# Performance and Tuning
In general, best performance is achieved on recent Linux 3.x kernels and using MySQL, although many of the largest PowerDNS installations are based on PostgreSQL. FreeBSD also performs very well.

Database servers can require configuration to achieve decent performance. It is especially worth noting that several vendors ship PostgreSQL with a slow default configuration.

**Warning**: When deploying (large scale) IPv6, please be aware some Linux distributions leave IPv6 routing cache tables at very small default values. Please check and if necessary raise `sysctl net.ipv6.route.max_size`.

# Performance related settings
When PowerDNS starts up it creates a number of threads to listen for packets. This is configurable with the [`receiver-threads`](settings.md#receiver-threads) setting which defines how many sockets will be opened by the powerdns process. In versions of linux before kernel 3.9 having too many receiver threads set up resulted in decreased performance due to socket contention between multiple CPUs - the typical sweet spot was 3 or 4. For optimal performance on kernel 3.9 and following with [`reuseport`](settings.md#reuseport) enabled you'll typically want a receiver thread for each core on your box if backend latency/performance is not an issue and you want top performance.

Different backends will have different characteristics - some will want to have more parallel instances than others. In general, if your backend is latency bound, like most relational databases are, it pays to open more backends.

This is done with the [`distributor-threads`](settings.md#distributor-threads) setting which says how many distributors will be opened for each receiver thread. Of special importance is the choice between 1 or more backends. In case of only 1 thread, PowerDNS reverts to unthreaded operation which may be a lot faster, depending on your operating system and architecture.

Another very important setting is [`cache-ttl`](settings.md#cache-ttl). PowerDNS caches entire packets it sends out so as to save the time to query backends to assemble all data. The default setting of 20 seconds may be low for high traffic sites, a value of 60 seconds rarely leads to problems.

Some PowerDNS operators set cache-ttl to many hours or even days, and use [`pdns_control`](running.md#pdns_control)` purge` to selectively or globally notify PowerDNS of changes made in the backend. Also look at the [Query Cache](#query-cache) described in this chapter. It may materially improve your performance.

To determine if PowerDNS is unable to keep up with packets, determine the value of the [`qsize-q`](../common/logging.md#counters) variable. This represents the number of packets waiting for database attention. During normal operations the queue should be small.

Logging truly kills performance as answering a question from the cache is an order of magnitude less work than logging a line about it. Busy sites will prefer to turn [`log-dns-details`](settings.md#log-dns-details) off.

# Packet Cache
PowerDNS by default uses the 'Packet Cache' to recognise identical questions and supply them with identical answers, without any further processing. The default time to live is 10 seconds. It has been observed that the utility of the packet cache increases with the load on your nameserver.

Not all backends may benefit from the packetcache. If your backend is memory based and does not lead to context switches, the packetcache may actually hurt performance.

The size of the packetcache can be observed with `/etc/init.d/pdns show packetcache-size`

# Query Cache
Besides entire packets, PowerDNS can also cache individual backend queries. Each DNS query leads to a number of backend queries, the most obvious additional backend query is the check for a possible CNAME. So, when a query comes in for the 'A' record for 'www.powerdns.com', PowerDNS must first check for a CNAME for 'www.powerdns.com'.

The Query Cache caches these backend queries, many of which are quite repetitive. PowerDNS only caches queries with no answer, or with exactly one. In the future this may be expanded but this lightweight solution is very simple and therefore fast.

Most gain is made from caching negative entries, ie, queries that have no answer. As these take little memory to store and are typically not a real problem in terms of speed-of-propagation, the default TTL for negative queries is a rather high 60 seconds.

This only is a problem when first doing a query for a record, adding it, and immediately doing a query for that record again. It may then take up to 60 seconds to appear. Changes to existing records however do not fall under the negative query ttl ([`negquery-cache-ttl`](settings.md#negquery-cache-ttl)), but under the generic [`query-cache-ttl`](settings.md#query-cache-ttl) which defaults to 20 seconds.

The default values should work fine for many sites. When tuning, keep in mind that the Query Cache mostly saves database access but that the Packet Cache also saves a lot of CPU because 0 internal processing is done when answering a question from the Packet Cache.

# Performance Monitoring
## Counters & variables
A number of counters and variables are set during PowerDNS Authoritative Server operation.

### Counters
All counters that show the "number of X" count since the last startup of the
daemon.

* `corrupt-packets`: Number of corrupt packets received
* `deferred-cache-inserts`: Number of cache inserts that were deferred because of maintenance
* `deferred-cache-lookup`: Number of cache lookups that were deferred because of maintenance
* `dnsupdate-answers`: Number of DNS update packets successfully answered
* `dnsupdate-changes`: Total number of changes to records from DNS update
* `dnsupdate-queries`: Number of DNS update packets received
* `dnsupdate-refused`: Number of DNS update packets that were refused
* `incoming-notifications`: Number of NOTIFY packets that were received
* `key-cache-size`: Number of entries in the key cache
* `latency`: Average number of microseconds a packet spends within PowerDNS
* `meta-cache-size`: Number of entries in the metadata cache
* `overload-drops`: Number of questions dropped because backends overloaded 
* `packetcache-hit`: Number of packets which were answered out of the cache
* `packetcache-miss`: Number of times a packet could not be answered out of the cache
* `packetcache-size`: Amount of packets in the packetcache
* `qsize-q`: Number of packets waiting for database attention
* `query-cache-hit`: Number of hits on the [query cache](performance.md#query-cache)
* `query-cache-miss`: Number of misses on the [query cache](performance.md#query-cache)
* `rd-queries`: Number of packets sent by clients requesting recursion (regardless of if we'll be providing them with recursion). Since 3.4.0.
* `recursing-answers`: Number of packets we supplied an answer to after recursive processing
* `recursing-questions`: Number of packets we performed recursive processing for
* `recursion-unanswered`: Number of packets we sent to our recursor, but did not get a timely answer for. Since 3.4.0.
* `security-status`: Security status based on [security polling](../common/security.md#implementation)
* `servfail-packets`: Amount of packets that could not be answered due to database problems
* `signature-cache-size`: Number of entries in the signature cache
* `signatures`: Number of DNSSEC signatures created
* `sys-msec`: Number of CPU miliseconds sent in system time
* `tcp-answers-bytes`: Total number of answer bytes sent over TCP (since 4.0.0)
* `tcp-answers`: Number of answers sent out over TCP
* `tcp-queries`: Number of questions received over TCP
* `tcp4-answers-bytes`: Total number of answer bytes sent over TCPv4 (since 4.0.0)
* `tcp4-answers`: Number of answers sent out over TCPv4
* `tcp4-queries`: Number of questions received over TCPv4
* `tcp6-answers-bytes`: Total number of answer bytes sent over TCPv6 (since 4.0.0)
* `tcp6-answers`: Number of answers sent out over TCPv6
* `tcp6-queries`: Number of questions received over TCPv6
* `timedout-packets`: Amount of packets that were dropped because they had to wait too long internally
* `udp-answers-bytes`: Total number of answer bytes sent over UDP
* `udp-answers`: Number of answers sent out over UDP
* `udp-do-queries`: Number of queries received with the DO (DNSSEC OK) bit set
* `udp-in-errors`: Number of packets, received faster than the OS could process them
* `udp-noport-errors`: Number of UDP packets where an ICMP response was received that the remote port was not listening
* `udp-queries`: Number of questions received over UDP
* `udp-recvbuf-errors`: Number of errors caused in the UDP receive buffer
* `udp-sndbuf-errors`: Number of errors caused in the UDP send buffer
* `udp4-answers-bytes`: Total number of answer bytes sent over UDPv4 (Since 4.0.0)
* `udp4-answers`: Number of answers sent out over UDPv4
* `udp4-queries`: Number of questions received over UDPv4
* `udp6-answers-bytes`: Total number of answer bytes sent over UDPv6 (Since 4.0.0)
* `udp6-answers`: Number of answers sent out over UDPv6
* `udp6-queries`: Number of questions received over UDPv6
* `uptime`: Uptime in seconds of the daemon
* `user-msec`: Number of milliseconds spend in CPU 'user' time

### Ring buffers
Besides counters, PowerDNS also maintains the ringbuffers. A ringbuffer records events, each new event gets a place in the buffer until it is full. When full, earlier entries get overwritten, hence the name 'ring'.

By counting the entries in the buffer, statistics can be generated. These statistics can currently only be viewed using the webserver and are in fact not even collected without the webserver running.

The following ringbuffers are available:

* **logmessages**: All messages logged
* **noerror-queries**: Queries for existing records but for a type we don't have.
Queries for, say, the AAAA record of a domain, when only an A is available. Queries are listed in the following format: name/type. So an AAAA query for pdns.powerdns.com looks like pdns.powerdns.com/AAAA.
* **nxdomain-queries**: Queries for non-existing records within existing domains.
If PowerDNS knows it is authoritative over a domain, and it sees a question for a record in that domain that does not exist, it is able to send out an authoritative 'no such domain' message. Indicates that hosts are trying to connect to services really not in your zone.
* **udp-queries**: All UDP queries seen.
* **remotes**: Remote server IP addresses.
Number of hosts querying PowerDNS. Be aware that UDP is anonymous - person A can send queries that appear to be coming from person B.
* **remote-corrupts**: Remotes sending corrupt packets.
Hosts sending PowerDNS broken packets, possibly meant to disrupt service. Be aware that UDP is anonymous - person A can send queries that appear to be coming from person B.
* **remote-unauth**: Remotes querying domains for which we are not authoritative.
It may happen that there are misconfigured hosts on the internet which are configured to think that a PowerDNS installation is in fact a resolving nameserver. These hosts will not get useful answers from PowerDNS. This buffer lists hosts sending queries for domains which PowerDNS does not know about.
* **servfail-queries**: Queries that could not be answered due to backend errors.
For one reason or another, a backend may be unable to extract answers for a certain domain from its storage. This may be due to a corrupt database or to inconsistent data. When this happens, PowerDNS sends out a 'servfail' packet indicating that it was unable to answer the question. This buffer shows which queries have been causing servfails.
* **unauth-queries**: Queries for domains that we are not authoritative for.
If a domain is delegated to a PowerDNS instance, but the backend is not made aware of this fact, questions come in for which no answer is available, nor is the authority. Use this ringbuffer to spot such queries.
