# Recursor Statistics
The `rec_control get` command can be used to query the following statistics, either single keys or multiple statistics at once:

* `all-outqueries`: counts the number of outgoing UDP queries since starting
* `answers-slow`: counts the number of queries answered after 1 second
* `answers0-1`: counts the number of queries answered within 1 millisecond
* `answers1-10`: counts the number of queries answered within 10 milliseconds
* `answers10-100`: counts the number of queries answered within 100 milliseconds
* `answers100-1000`: counts the number of queries answered within 1 second
* `auth4-answers-slow`: counts the number of queries answered by auth4s after 1 second (4.0)
* `auth4-answers0-1`: counts the number of queries answered by auth4s within 1 millisecond (4.0)
* `auth4-answers1-10`: counts the number of queries answered by auth4s within 10 milliseconds (4.0)
* `auth4-answers10-100`: counts the number of queries answered by auth4s within 100 milliseconds (4.0)
* `auth4-answers100-1000`: counts the number of queries answered by auth4s within 1 second (4.0)
* `auth6-answers-slow`: counts the number of queries answered by auth6s after 1 second (4.0)
* `auth6-answers0-1`: counts the number of queries answered by auth6s within 1 millisecond (4.0)
* `auth6-answers1-10`: counts the number of queries answered by auth6s within 10 milliseconds (4.0)
* `auth6-answers10-100`: counts the number of queries answered by auth6s within 100 milliseconds (4.0)
* `auth6-answers100-1000`: counts the number of queries answered by auth6s within 1 second (4.0)
* `cache-bytes`: size of the cache in bytes (since 3.3.1)
* `cache-entries`: shows the number of entries in the cache
* `cache-hits`: counts the number of cache hits since starting, this does **not** include hits that got answered from the packet-cache
* `cache-misses`: counts the number of cache misses since starting
* `case-mismatches`: counts the number of mismatches in character case since starting
* `chain-resends`: number of queries chained to existing outstanding query
* `client-parse-errors`: counts number of client packets that could not be parsed
* `concurrent-queries`: shows the number of MThreads currently running
* `dlg-only-drops`: number of records dropped because of delegation only setting
* `dnssec-queries`: number of queries received with the DO bit set
* `dnssec-result-bogus`: number of DNSSEC validations that had the Bogus state
* `dnssec-result-indeterminate`: number of DNSSEC validations that had the Indeterminate state
* `dnssec-result-insecure`: number of DNSSEC validations that had the Insecure state
* `dnssec-result-nta`: number of DNSSEC validations that had the NTA (negative trust anchor) state
* `dnssec-result-secure`: number of DNSSEC validations that had the Secure state
* `dnssec-validations`: number of DNSSEC validations performed
* `dont-outqueries`: number of outgoing queries dropped because of 'dont-query' setting (since 3.3)
* `edns-ping-matches`: number of servers that sent a valid EDNS PING response
* `edns-ping-mismatches`: number of servers that sent an invalid EDNS PING response
* `failed-host-entries`: number of servers that failed to resolve
* `ignored-packets`: counts the number of non-query packets received on server sockets that should only get query packets
* `ipv6-outqueries`: number of outgoing queries over IPv6
* `ipv6-questions`: counts all end-user initiated queries with the RD bit set, received over IPv6 UDP
* `malloc-bytes`: returns the number of bytes allocated by the process (broken, always returns 0)
* `max-mthread-stack`: maximum amount of thread stack ever used
* `negcache-entries`: shows the number of entries in the negative answer cache
* `no-packet-error`: number of errorneous received packets
* `noedns-outqueries`: number of queries sent out without EDNS
* `noerror-answers`: counts the number of times it answered NOERROR since starting
* `noping-outqueries`: number of queries sent out without ENDS PING
* `nsset-invalidations`: number of times an nsset was dropped because it no longer worked
* `nsspeeds-entries`: shows the number of entries in the NS speeds map
* `nxdomain-answers`: counts the number of times it answered NXDOMAIN since starting
* `outgoing-timeouts`: counts the number of timeouts on outgoing UDP queries since starting
* `outgoing4-timeouts`: counts the number of timeouts on outgoing UDP IPv4 queries since starting (since 4.0)
* `outgoing6-timeouts`: counts the number of timeouts on outgoing UDP IPv6 queries since starting (since 4.0)
* `over-capacity-drops`: questions dropped because over maximum concurrent query limit (since 3.2)
* `packetcache-bytes`: size of the packet cache in bytes (since 3.3.1)
* `packetcache-entries`: size of packet cache (since 3.2)
* `packetcache-hits`: packet cache hits (since 3.2)
* `packetcache-misses`: packet cache misses (since 3.2)
* `policy-drops`: packets dropped because of (Lua) policy decision
* `policy-result-noaction`: packets that were not actioned upon by the RPZ/filter engine
* `policy-result-drop`: packets that were dropped by the RPZ/filter engine
* `policy-result-nxdomain`: packets that were replied to with NXDOMAIN by the RPZ/filter engine
* `policy-result-nodata`: packets that were replied to with no data by the RPZ/filter engine
* `policy-result-truncate`: packets that were forced to TCP by the RPZ/filter engine
* `policy-result-custom`: packets that were sent a custom answer by the RPZ/filter engine
* `qa-latency`: shows the current latency average, in microseconds, exponentially weighted over past 'latency-statistic-size' packets
* `questions`: counts all end-user initiated queries with the RD bit set
* `resource-limits`: counts number of queries that could not be performed because of resource limits
* `security-status`: security status based on [security polling](../common/security.md#implementation)
* `server-parse-errors`: counts number of server replied packets that could not be parsed
* `servfail-answers`: counts the number of times it answered SERVFAIL since starting
* `spoof-prevents`: number of times PowerDNS considered itself spoofed, and dropped the data
* `sys-msec`: number of CPU milliseconds spent in 'system' mode
* `tcp-client-overflow`: number of times an IP address was denied TCP access because it already had too many connections
* `tcp-clients`: counts the number of currently active TCP/IP clients
* `tcp-outqueries`: counts the number of outgoing TCP queries since starting
* `tcp-questions`: counts all incoming TCP queries (since starting)
* `throttle-entries`: shows the number of entries in the throttle map
* `throttled-out`: counts the number of throttled outgoing UDP queries since starting
* `throttled-outqueries`: idem to throttled-out
* `too-old-drops`: questions dropped that were too old
* `unauthorized-tcp`: number of TCP questions denied because of allow-from restrictions
* `unauthorized-udp`: number of UDP questions denied because of allow-from restrictions
* `unexpected-packets`: number of answers from remote servers that were unexpected (might point to spoofing)
* `unreachables`: number of times nameservers were unreachable since starting
* `uptime`: number of seconds process has been running (since 3.1.5)
* `user-msec`: number of CPU milliseconds spent in 'user' mode

In the `pdns/tools/rrd/` subdirectory a number of rrdtool scripts is provided to
make nice graphs of all these numbers. Use `rec_control get-all` to get all
statistics in one go.

It should be noted that answers0-1 + answers1-10 + answers10-100 + answers100-1000 +
answers-slow + packetcache-hits + over-capacity-drops + policy-drops = questions.

Also note that unauthorized-tcp and unauthorized-udp packets do not end up in
the 'questions' count.

Every half hour or so, the recursor outputs a line with statistics. More
infrastructure is planned so as to allow for Cricket or MRTG graphs. To force
the output of statistics, send the process a SIGUSR1. A line of statistics looks
like this:

```
Feb 10 14:16:03 stats: 125784 questions, 13971 cache entries, 309 negative entries, 84% cache hits, outpacket/query ratio 37%, 12% throttled
```

This means that there are 13791 different names cached, which each may have
multiple records attached to them. There are 309 items in the negative cache,
items of which it is known that don't exist and won't do so for the near future.
84% of incoming questions could be answered without any additional queries going
out to the net.

The outpacket/query ratio means that on average, 0.37 packets were needed to
answer a question. Initially this ratio may be well over 100% as additional
queries may be needed to actually recurse the DNS and figure out the addresses
of nameservers.

Finally, 12% of queries were not performed because identical queries had gone out
previously, saving load on servers worldwide.
