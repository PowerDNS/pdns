# Performance and Tuning
## General advice
In general, best performance is achieved on recent Linux 3.x kernels and using MySQL, although many of the largest PowerDNS installations are based on PostgreSQL. FreeBSD also performs very well.

Database servers can require configuration to achieve decent performance. It is especially worth noting that several vendors ship PostgreSQL with a slow default configuration.

**Warning**: When deploying (large scale) IPv6, please be aware some Linux distributions leave IPv6 routing cache tables at very small default values. Please check and if necessary raise `sysctl net.ipv6.route.max_size`.

## Performance related settings
When PowerDNS starts up it creates a number of threads to listen for packets. This is configurable with the [`receiver-threads`](settings.md#receiver-threads) setting which defines how many sockets will be opened by the powerdns process. In versions of linux before kernel 3.9 having too many receiver threads set up resulted in decreased performance due to socket contention between multiple CPUs - the typical sweet spot was 3 or 4. For optimal performance on kernel 3.9 and following with [`reuseport`](settings.md#reuseport) enabled you'll typically want a receiver thread for each core on your box if backend latency/performance is not an issue and you want top performance.

Different backends will have different characteristics - some will want to have more parallel instances than others. In general, if your backend is latency bound, like most relational databases are, it pays to open more backends.

This is done with the [`distributor-threads`](settings.md#distributor-threads) setting which says how many distributors will be opened for each receiver thread. Of special importance is the choice between 1 or more backends. In case of only 1 thread, PDNS reverts to unthreaded operation which may be a lot faster, depending on your operating system and architecture.

Another very important setting is [`cache-ttl`](settings.md#cache-ttl). PDNS caches entire packets it sends out so as to save the time to query backends to assemble all data. The default setting of 20 seconds may be low for high traffic sites, a value of 60 seconds rarely leads to problems.

Some PDNS operators set cache-ttl to many hours or even days, and use [`pdns_control`](../appendix/pdns-internals.md#pdns_control)` purge` to selectively or globally notify PDNS of changes made in the backend. Also look at the [Query Cache](#query-cache) described in this chapter. It may materially improve your performance.

To determine if PDNS is unable to keep up with packets, determine the value of the [`qsize-q`](logging.md#counters) variable. This represents the number of packets waiting for database attention. During normal operations the queue should be small.

Logging truly kills performance as answering a question from the cache is an order of magnitude less work than logging a line about it. Busy sites will prefer to turn [`log-dns-details`](settings.md#log-dns-details) off.

# Packet Cache
PDNS by default uses the 'Packet Cache' to recognise identical questions and supply them with identical answers, without any further processing. The default time to live is 10 seconds. It has been observed that the utility of the packet cache increases with the load on your nameserver.

Not all backends may benefit from the packetcache. If your backend is memory based and does not lead to context switches, the packetcache may actually hurt performance.

The size of the packetcache can be observed with `/etc/init.d/pdns show packetcache-size`

# Query Cache
Besides entire packets, PDNS can also cache individual backend queries. Each DNS query leads to a number of backend queries, the most obvious additional backend query is the check for a possible CNAME. So, when a query comes in for the 'A' record for 'www.powerdns.com', PDNS must first check for a CNAME for 'www.powerdns.com'.

The Query Cache caches these backend queries, many of which are quite repetitive. PDNS only caches queries with no answer, or with exactly one. In the future this may be expanded but this lightweight solution is very simple and therefore fast.

Most gain is made from caching negative entries, ie, queries that have no answer. As these take little memory to store and are typically not a real problem in terms of speed-of-propagation, the default TTL for negative queries is a rather high 60 seconds.

This only is a problem when first doing a query for a record, adding it, and immediately doing a query for that record again. It may then take up to 60 seconds to appear. Changes to existing records however do not fall under the negative query ttl ([`negquery-cache-ttl`](settings.md#negquery-cache-ttl)), but under the generic [`query-cache-ttl`](settings.md#query-cache-ttl) which defaults to 20 seconds.

The default values should work fine for many sites. When tuning, keep in mind that the Query Cache mostly saves database access but that the Packet Cache also saves a lot of CPU because 0 internal processing is done when answering a question from the Packet Cache.
