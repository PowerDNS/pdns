Performance Guide
=================

To get the best out of the PowerDNS recursor, which is important if you are doing thousands of queries per second, please consider the following.

A busy server may need hundreds of file descriptors on startup, and deals with spikes better if it has that many available later on.
Linux by default restricts processes to 1024 file descriptors, which should suffice most of the time, but Solaris has a default limit of 256.
This can be raised using the ``ulimit`` command or via the ``LimitNOFILE`` unit directive when ``systemd`` is used.
FreeBSD has a default limit that is high enough for even very heavy duty use.

Limit the size of the caches to a sensible value.
Cache hit rate does not improve meaningfully beyond a few million :ref:`setting-yaml-recordcache.max_entries`, reducing the memory footprint reduces CPU cache misses.
See below for more information about the various caches.

When deploying (large scale) IPv6, please be aware some Linux distributions leave IPv6 routing cache tables at very small default values.
Please check and if necessary raise ``sysctl net.ipv6.route.max_size``.

Set :ref:`setting-yaml-recursor.threads` to your number of CPU cores minus the number of distributor threads.

Threading and distribution of queries
-------------------------------------

When running with several threads, you can either ask PowerDNS to start one or more special threads to dispatch the incoming queries to the workers by setting :ref:`setting-yaml-incoming.pdns_distributes_queries` to ``yes``, or let the worker threads handle the incoming queries themselves.
The latter is the default since version 4.9.0.

The dispatch thread enabled by :ref:`setting-yaml-incoming.pdns_distributes_queries` tries to send the same queries to the same thread to maximize the cache-hit ratio.
If the incoming query rate is so high that the dispatch thread becomes a bottleneck, you can increase :ref:`setting-yaml-incoming.distributor_threads` to use more than one.

If :ref:`setting-yaml-incoming.pdns_distributes_queries` is set to ``false`` and either ``SO_REUSEPORT`` support is not available or the :ref:`setting-yaml-incoming.reuseport` directive is set to ``false``, all worker threads share the same listening sockets.

This prevents a single thread from having to handle every incoming queries, but can lead to thundering herd issues where all threads are awoken at once when a query arrives.

If ``SO_REUSEPORT`` support is available and :ref:`setting-yaml-incoming.reuseport` is set to ``true``, which is the
default since version 4.9.0, separate listening sockets are opened for each worker thread and the query distributions is handled by the kernel, avoiding any thundering herd issue as well as preventing the distributor thread from becoming the bottleneck.
The next section discusses how to determine if the mechanism is working properly.

.. _worker_imbalance:

Imbalance
^^^^^^^^^
Due to the nature of the distribution method used by the kernel imbalance with the new default settings of :ref:`setting-yaml-incoming.reuseport` and :ref:`setting-yaml-incoming.pdns_distributes_queries` may occur if you have very few clients.
Imbalance can be observed by reading the periodic statistics reported by :program:`Recursor`::

  Jun 26 11:06:41 pepper pdns-recursor[10502]: msg="Queries handled by thread" subsystem="stats" level="0" prio="Info" tid="0" ts="1687770401.359" count="7" thread="0"
  Jun 26 11:06:41 pepper pdns-recursor[10502]: msg="Queries handled by thread" subsystem=" stats" level="0" prio="Info" tid="0" ts="1687770401.359" count="535167" thread="1"
  Jun 26 11:06:41 pepper pdns-recursor[10502]: msg="Queries handled by thread" subsystem=" stats" level="0" prio="Info" tid="0" ts="1687770401.359" count="5" thread="2"

In the above log lines we see that almost all queries are processed by thread 1.
This can typically be observed when using ``dnsdist`` in front of :program:`Recursor`.

When using ``dnsdist`` with a single ``newServer`` to a recursor instance in its configuration, the kernel will regard ``dnsdist`` as a single client unless you use the ``sockets`` parameter to ``newServer`` to increase the number of source ports used by ``dnsdist``.
The following guideline applies for the ``dnsdist`` case:

- Be generous with the ``sockets`` setting of ``newServer``.
  A starting points is to configure twice as many sockets as :program:`Recursor` threads.
- As long as the threads of the :program:`Recursor` as not overloaded, some imbalance will not impact performance significantly.
- If you want to reduce imbalance, increase the value of ``sockets`` even more.

Non-Linux systems
^^^^^^^^^^^^^^^^^
On some systems setting :ref:`setting-yaml-incoming.reuseport` to ``true`` does not have the desired effect at all.
If your systems shows great imbalance in the number of queries processed per thread (as reported by the periodic statistics report), try switching :ref:`setting-yaml-incoming.reuseport` to ``false`` and/or setting  :ref:`setting-yaml-incoming.pdns_distributes_queries` to ``true``.

.. versionadded:: 4.1.0
   The :ref:`setting-yaml-recursor.cpu_map` parameter can be used to pin worker threads to specific CPUs, in order to keep caches as warm as possible and optimize memory access on NUMA systems.

.. versionadded:: 4.2.0
   The :ref:`setting-yaml-incoming.distributor_threads` parameter can be used to run more than one distributor thread.

.. versionchanged:: 4.9.0
   The :ref:`setting-yaml-incoming.reuseport` parameter now defaults to ``yes``.

.. versionchanged:: 4.9.0
   The :ref:`setting-yaml-incoming.pdns_distributes_queries` parameter now defaults to ``no``.


MTasker and MThreads
--------------------

PowerDNS :program:`Recursor` uses a cooperative multitasking in userspace called ``MTasker``, based either on ``boost::context`` if available, or on ``System V ucontexts`` otherwise. For maximum performance, please make sure that your system supports ``boost::context``, as the alternative has been known to be quite slower.

The maximum number of simultaneous MTasker threads, called ``MThreads``, can be tuned via :ref:`setting-yaml-recursor.max_mthreads`, as the default value of 2048 might not be enough for large-scale installations.
This setting limits the number of mthreads *per physical (Posix) thread*.
The threads that create mthreads are the distributor and worker threads.

When a ``MThread`` is started, a new stack is dynamically allocated for it. The size of that stack can be configured via the :ref:`setting-yaml-recursor.stack_size` parameter, whose default value is 200 kB which should be enough in most cases.

To reduce the cost of allocating a new stack for every query, the recursor can cache a small amount of stacks to make sure that the allocation stays cheap. This can be configured via the :ref:`setting-yaml-recursor.stack_cache_size` setting.
This limit is per physical (Posix) thread.
The only trade-off of enabling this cache is a slightly increased memory consumption, at worst equal to the number of stacks specified by :ref:`setting-yaml-recursor.stack_cache_size` multiplied by the size of one stack, itself specified via :ref:`setting-yaml-recursor.stack_size`.

Linux limits the number of memory mappings a process can allocate by the ``vm.max_map_count`` kernel parameter.
A single ``MThread`` stack can take up to 3 memory mappings.
Starting with version 4.9, it is advised to check and if needed update the value of ``sysctl vm.max_map_count`` to make sure that the :program:`Recursor` can allocate enough stacks under load; suggested value is at least ``4 * (threads + 2) * max-mthreads``.
Some Linux distributions use a default value of about one million, which should be enough for most configurations.
Other distributions default to 64k, which can be too low for large setups.

Performance tips
----------------

For best PowerDNS Recursor performance, use a recent version of your operating system, since this generally offers the best event multiplexer implementation available (``kqueue``, ``epoll``,  ``ports`` or ``/dev/poll``).

On AMD/Intel hardware, wherever possible, run a 64-bit binary. This delivers a nearly twofold performance increase.
On UltraSPARC, there is no need to run with 64 bits.

Consider performing a 'profiled build' by building with ``gprof`` support enabled, running the recursor a bit then feed that info into the next build.
This is good for a 20% performance boost in some cases.

When running with >3000 queries per second, and running Linux versions prior to 2.6.17 on some motherboards, your computer may spend an inordinate amount of time working around an ACPI bug for each call to gettimeofday.
This is solved by rebooting with ``clock=tsc`` or upgrading to a 2.6.17 kernel.
This is relevant if dmesg shows ``Using pmtmr for high-res timesource``.

Memory usage
------------

:program:`Recursor` keeps all the data it needs in memory.
The default configuration uses a little more than 1GB when the caches are full.
Depending on configuration, memory usage can amount to many gigabytes for a large installation.

.. warning::
   Avoid swapping. The memory access patterns of :program:`Recursor` are random. This means
   that it will cause trashing (the OS spending lots of time pulling in and writing out memory
   pages) if :program:`Recursor` uses more physical memory than available and performance will be severely impacted.

Below the memory usage observed for a specific test case are described.
Please note that depending on OS, version of system libraries, version of the :program:`Recursor`, features used and usage patterns these numbers may vary.
Test and observe your system to learn more about the memory requirements specific to your case.

The most important subsystems that use memory are:

- The packet cache. The amount of memory used in a test case was about 500 bytes per entry
- The record cache. The amount of memory used in a test case was about 850 bytes per entry
- Authoritative zones loaded. Memory usage is dependent on the size and number loaded.
- RPZ zones loaded. Memory usage is dependent on the size and number loaded.
- NOD DBs. Memory usage is dependent on specific settings of this subsystem.

An estimate for the memory used by its caches for a :program:`Recursor` having 2 million record cache entries and 1 million packet cache entries is ``2e6 * 850 * + 1e6 * 500 = about 2GB``.

Connection tracking and firewalls
---------------------------------

A Recursor under high load puts a severe stress on any stateful (connection tracking) firewall, so much so that the firewall may fail.

Specifically, many Linux distributions run with a connection tracking firewall configured.
For high load operation (thousands of queries/second), It is advised to either turn off iptables completely, or use the ``NOTRACK`` feature to make sure client DNS traffic bypasses the connection tracking.

Sample Linux command lines would be::

    ## IPv4
    ## NOTRACK rules for 53/udp, keep in mind that you also need your regular rules for 53/tcp
    iptables -t raw -I OUTPUT -p udp --sport 53 -j CT --notrack
    iptables -t raw -I PREROUTING -p udp --dport 53 -j CT --notrack
    iptables -I INPUT -p udp --dport 53 -j ACCEPT

    ## IPv6
    ## NOTRACK rules for 53/udp, keep in mind that you also need your regular rules for 53/tcp
    ip6tables -t raw -I OUTPUT -p udp --sport 53 -j CT --notrack
    ip6tables -t raw -I PREROUTING -p udp --dport 53 -j CT --notrack
    ip6tables -I INPUT -p udp --dport 53 -j ACCEPT

When using FirewallD (Centos 7+ / Red Hat 7+ / Fedora 21+), connection tracking can be disabled via direct rules.
The settings can be made permanent by using the ``--permanent`` flag::

    ## IPv4
    ## NOTRACK rules for 53/udp, keep in mind that you also need your regular rules for 53/tcp
    firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p udp --sport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p udp --dport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p udp --dport 53 -j ACCEPT

    ## IPv6
    ## NOTRACK rules for 53/udp, keep in mind that you also need your regular rules for 53/tcp
    firewall-cmd --direct --add-rule ipv6 raw OUTPUT 0 -p udp --sport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv6 raw PREROUTING 0 -p udp --dport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -p udp --dport 53 -j ACCEPT

Following the instructions above, you should be able to attain very high query rates.

Tuning Incoming TCP and Out-of-Order processing
-----------------------------------------------

In general TCP uses more resources than UDP, so beware!
It is impossible to give hard numbers for the various parameters as each site is different.
Instead we describe the mechanism and relevant metrics so you can study your setup and change the proper settings if needed.

Each incoming TCP connection uses a file descriptor in addition to the file descriptors for other purposes, like contacting authoritative servers.
When the recursor starts up, it will check if enough file descriptors are available and complain if not.

When a query is received over a TCP connection, first the packet cache is consulted.
If an answer is found it will be returned immediately.
If no answer is found, the Recursor will process :ref:`setting-yaml-incoming.max_concurrent_requests_per_tcp_connection` queries per incoming TCP connection concurrently.
If more than this number of queries is pending for this TCP connection, the remaining queries will stay in the TCP receive buffer to be processed later.
Each of the queries processed will consume an mthread until processing is done.
A response to a query is sent immediately when it becomes available; the response can be sent before other responses to queries that were received earlier by the Recursor.
This is the Out-of-Order feature which greatly enhances performance, as a single slow query does not prevent other queries to be processed.

Before version 5.0.0, TCP queries are processed by either the distributer thread(s) if :ref:`setting-yaml-incoming.pdns_distributes_queries` is true, or by worker threads if :ref:`setting-yaml-incoming.pdns_distributes_queries` is false.
Starting with version 5.0.0, :program:`Recursor` has dedicated thread(s) processing TCP queries.

The maximum number of mthreads consumed by TCP queries is :ref:`setting-yaml-incoming.max_tcp_clients` times :ref:`setting-yaml-incoming.max_concurrent_requests_per_tcp_connection`.
Before version 5.0.0, if :ref:`setting-yaml-incoming.pdns_distributes_queries` is false, this number should be (much) lower than :ref:`setting-yaml-recursor.max_mthreads`, to also allow UDP queries to be handled as these also consume mthreads.
Note that :ref:`setting-yaml-recursor.max_mthreads` is a per Posix thread setting.
This means that the global maximum number of mthreads  is (#distributor threads + #worker threads) * max-mthreads.

If you expect few clients, you can increase :ref:`setting-yaml-incoming.max_concurrent_requests_per_tcp_connection`, to allow more concurrency per TCP connection.
If you expect many clients and you have increased :ref:`setting-yaml-incoming.max_tcp_clients`, reduce :ref:`setting-yaml-incoming.max_concurrent_requests_per_tcp_connection` number to prevent mthread starvation or increase the maximum number of mthreads.

To increase the maximum number of concurrent queries consider increasing  :ref:`setting-yaml-recursor.max_mthreads`, but be aware that each active mthread consumes more than 200k of memory.
To see the current number of mthreads in use consult the :doc:`metrics` ``concurrent-queries`` metric.
If a query could not be handled due to mthread shortage, the ``over-capacity-drops`` metric is increased.

As an example, if you have typically 200 TCP clients, and the default maximum number of mthreads of 2048, a good number of concurrent requests per TCP connection would be 5. Assuming a worst case packet cache hit ratio, if all 200 TCP clients fill their connections with queries, about half (5 * 200) of the mthreads would be used by incoming TCP queries, leaving the other half for incoming UDP queries.
Note that starting with version 5.0.0, TCP queries are processed by dedicated TCP thread(s), so the sharing of mthreads between UDP and TCP queries no longer applies.

The total number of incoming TCP connections is limited by :ref:`setting-yaml-incoming.max_tcp_clients`.
There is also a per client address limit: :ref:`setting-yaml-incoming.max_tcp_per_client` to limit the impact of a single client.
Consult the :doc:`metrics` ``tcp-clients`` metric for the current number of TCP connections and the ``tcp-client-overflow`` metric to see if client connection attempts were rejected because there were too many existing connections from a single address.

.. _tcp-fast-open-support:

TCP Fast Open Support
---------------------
On Linux systems, the recursor can use TCP Fast Open for passive (incoming, since 4.1) and active (outgoing, since 4.5) TCP connections.
TCP Fast Open allows the initial SYN packet to carry data, saving one network round-trip.
For details, consult :rfc:`7413`.

On Linux systems, to enable TCP Fast Open, it might be needed to change the value of the ``net.ipv4.tcp_fastopen`` sysctl.
Value 0 means Fast Open is disabled, 1 is only use Fast Open for active connections, 2 is only for passive connections and 3 is for both.

The operation of TCP Fast Open can be monitored by looking at these kernel metrics::

    netstat -s | grep TCPFastOpen

Please note that if active (outgoing) TCP Fast Open attempts fail in particular ways, the Linux kernel stops using active TCP Fast Open for a while for all connections, even connection to servers that previously worked.
This behaviour can be monitored by watching the ``TCPFastOpenBlackHole`` kernel metric and influenced by setting the ``net.ipv4.tcp_fastopen_blackhole_timeout_sec`` sysctl.
While developing active TCP Fast Open, it was needed to set ``net.ipv4.tcp_fastopen_blackhole_timeout_sec`` to zero to circumvent the issue, since it was triggered regularly when connecting to authoritative nameservers that did not respond.

At the moment of writing, some Google operated nameservers (both recursive and authoritative) indicate Fast Open support in the TCP handshake, but do not accept the cookie they sent previously and send a new one for each connection.
Google is working to fix this.

If you operate an anycast pool of machines, make them share the TCP Fast Open Key by setting the ``net.ipv4.tcp_fastopen_key`` sysctl; otherwise, you will create a similar issue some Google servers have.

To determine a good value for the :ref:`setting-yaml-incoming.tcp_fast_open` setting, watch the ``TCPFastOpenListenOverflow`` metric.
If this value increases often, the value might be too low for your traffic, but note that increasing it will use kernel resources.

Running with a local root zone 
------------------------------
Running with a local root zone as described in :rfc:`8806` can help reduce traffic to the root servers and reduce response times for clients.
Since 4.6.0 PowerDNS Recursor supports two ways of doing this.

Running a local Authoritative Server for the root zone

- The first method is to have a local Authoritative Server that has a copy of the root zone and forward queries to it.
  Setting up an PowerDNS Authoritative Server to serve a copy of the root zone looks like:

      pdnsutil create-secondary-zone . ip1 ip2

  where ``ip1`` and  ``ip2`` are servers willing to serve an AXFR for the root zone; :rfc:`8806` contains a list of candidates in appendix A. The Authoritative Server will periodically make sure its copy of the root zone is up-to-date.
  The next step is to configure a forward zone to the IP ``ip`` of the Authoritative Server in the settings file or the Recursor:

    forward-zones=.=ip

  The Recursor will use the Authoritative Server to ask questions about the root zone, but if it learns about delegations still follow those.
  Multiple Recursors can use this Authoritative Server.

- The second method is to cache the root zone as described in :ref:`ztc`.
  Here each Recursor will download and fill its cache with the contents of the root zone.
  Depending on the ``timeout`` parameter,  this will be done once or periodically.
  Refer to :ref:`ztc` for details.

Recursor Caches
---------------

The PowerDNS Recursor contains a number of caches, or information stores:

Nameserver speeds cache
^^^^^^^^^^^^^^^^^^^^^^^

The "NSSpeeds" cache contains the average latency to all remote authoritative servers.

Negative cache
^^^^^^^^^^^^^^

The "Negcache" contains all domains known not to exist, or record types not to exist for a domain.

Recursor Cache
^^^^^^^^^^^^^^

The Recursor Cache contains all DNS knowledge gathered over time.
This is also known as the "record cache".

Packet Cache
^^^^^^^^^^^^

The Packet Cache contains previous answers sent to clients.
If a question comes in that matches a previous answer, this is sent back directly.

The Packet Cache is consulted first, immediately after receiving a packet.
This means that a high hitrate for the Packet Cache automatically lowers the cache hitrate of subsequent caches.

Measuring performance
---------------------

The PowerDNS Recursor exposes many :doc:`metrics <metrics>` that can be graphed and monitored.

.. _event-tracing:

Event Tracing
-------------
Event tracing is an experimental feature introduced in version 4.6.0 that allows following the internals of processing queries in more detail.

In certain spots in the resolving process event records are created that contain an identification of the event, a timestamp, potentially a value and an indication if this was the start or the end of an event. This is relevant for events that describe stages in the resolving process.

At this point in time event logs of queries can be exported using a protobuf log or they can be written to the log file.
Starting with version 5.3.0, the same information can also be exported as OpenTelemetry Traces data.

Note that this is an experimental feature that will change in upcoming releases.

Currently, an event protobuf message has the following definition:

.. code-block:: protobuf

    enum EventType {
                                                  // Range 0..99: Generic events
      CustomEvent = 0;                            // A custom event
      ReqRecv = 1;                                // A request was received
      PCacheCheck = 2;                            // A packet cache check was initiated or completed; value: bool cacheHit
      AnswerSent = 3;                             // An answer was sent to the client

                                                  // Range 100: Recursor events
      SyncRes = 100;                              // Recursor Syncres main function has started or completed; value: int rcode
      LuaGetTag = 101;                            // Events below mark start or end of Lua hook calls; value: return value of hook
      LuaGetTagFFI = 102;
      LuaIPFilter = 103;
      LuaPreRPZ = 104;
      LuaPreResolve = 105;
      LuaPreOutQuery = 106;
      LuaPostResolve = 107;
      LuaNoData = 108;
      LuaNXDomain = 109;
  }

.. code-block:: protobuf

    message Event {
      required uint64 ts = 1;
      required EventType event = 2;
      required bool start = 3;
      optional bool boolVal = 4;
      optional int64 intVal = 5;
      optional string stringVal = 6;
      optional bytes bytesVal = 7;
      optional string custom = 8;
    }
    repeated Event trace = 23;

Event traces can be enabled by either setting :ref:`setting-yaml-recursor.event_trace_enabled` or by using the :doc:`rec_control <manpages/rec_control.1>` subcommand ``set-event-trace-enabled``.

An example of a trace (timestamps are relative in nanoseconds) as shown  in the logfile:

.. code-block:: C

    - ReqRecv(70);
    - PCacheCheck(411964);
    - PCacheCheck(416783,0,done);
    - SyncRes(441811);
    - SyncRes(337233971,0,done);
     -AnswerSent(337266453)

The packet cache check event has two events.
The first signals the start of packet cache lookup, and the second signals the completion of the packet cache lookup with result 0 (not found).
The SynRec event also has two entries. The value (0) is the return value of the SyncRes function.

An example of a trace with a packet cache hit):

.. code-block:: C

    - ReqRecv(60);
    - PCacheCheck(22913);
    - PCacheCheck(113255,1,done);
    - AnswerSent(117493)

Here it can be seen that packet cache returns 1 (found).

An example where various Lua related events can be seen:

.. code-block:: C

    ReqRecv(150);
    PCacheCheck(26912);
    PCacheCheck(51308,0,done);
    LuaIPFilter(56868);
    LuaIPFilter(57149,0,done);
    LuaPreRPZ(82728);
    LuaPreRPZ(82918,0,done);
    LuaPreResolve(83479);
    LuaPreResolve(210621,0,done);
    SyncRes(217424);
    LuaPreOutQuery(292868);
    LuaPreOutQuery(292938,0,done);
    LuaPreOutQuery(24702079);
    LuaPreOutQuery(24702349,0,done);
    LuaPreOutQuery(43055303);
    LuaPreOutQuery(43055634,0,done);
    SyncRes(80470320,0,done);
    LuaPostResolve(80476592);
    LuaPostResolve(80476772,0,done);
    AnswerSent(80500247)

There is no packet cache hit, so SyncRes is called which does a couple of outgoing queries.

.. _opentelemetry_tracing:

OpenTelemetry Traces
^^^^^^^^^^^^^^^^^^^^

OpenTelemetry Traces are generated by setting :ref:`setting-yaml-recursor.event_trace_enabled` or by using the :doc:`rec_control <manpages/rec_control.1>` subcommand ``set-event-trace-enabled`` to a value that includes 4.

:program:`Recursor` will set the ``openTelemetryData`` field of ``dnsmessage.proto`` messages generated to contain OpenTelemetry Traces, encoded as Protobuf data.
The encoding used is defined in https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto.

OpenTelemetry Trace Conditions
""""""""""""""""""""""""""""""

Starting with version 5.4.0, the OpenTelemetry Trace data is only generated if :ref:`setting-yaml-recursor.event_trace_enabled` includes 4 *and* a matching condition from :ref:`setting-yaml-logging.opentelemetry_trace_conditions` evaluates to ``true``.

For a match to occur, the origin address of the query should match a subnet in `acls`.
If the proxy protocol is used, the source specified by the proxy protocol header is used to match.
If Table Based Proxy Mapping is active, the mapped address is used.

If a matching condition is found, the corresponding subconditions are evaluated.
If all mentioned subconditions are satisfied, the condition evaluates to ``true`` and OpenTelemetry Trace data is generated.
If a subcondition is absent, it is not relevant.
The following subconditions can be specified:

- ``qnames``: a suffixmatch with the incoming qname is done against the suffixes specified in ``qnames``.
- ``qtypes``: the qtype of the incoming query must be listed in ``qtypes``
- ``qid``: the query id of the incoming query must match ``qid``.
- ``edns_option_required``: the incoming query must have an EDNS option specifying the TraceID.
- ``traceid_only``: if ``true`` only the TraceID is picked up from EDNS data (if present) and placed into the protobuf `openTelemetryTraceID` field; no detailed `openTelemetryData` is produced.

In the following example, two conditions are specified:

.. code-block:: yaml

   logging:
     opentelemetry_trace_conditions:
       - acls: [127.0.0.1, '::1']
       - acls: [192.168.178.0/24]
         qnames: [a.very.specific.suffix]
         qtypes: ['A', 'AAAA']
         qid: 1234
         edns_option_required: true

The first condition specifies that all queries coming from ``127.0.0.1`` or ``::1`` should generate trace information.
No subconditions are relevant.

The second condition specifies that queries coming from the ``192.167.178.0/24`` subnet should generate trace info only if the query name is ``a.very.specific.suffix`` (or has that suffix), the query type is ``A`` or ``AAAA``, the query id is ``1234`` and the EDNS option containing a TraceID is present.

Queries coming from an IP not matching any of the mentioned subnets will not generate OpenTelemetry Trace information.

Note that only the source IP is used to select a condition to evaluate.
It is undefined what happens if a subnet occurs multiple times in all :ref:`setting-yaml-logging.opentelemetry_trace_conditions`.

To generate OpenTelemetry Trace information for all queries (matching the 5.3.x behaviour), the following condition can be used:

.. code-block:: yaml

   logging:
     opentelemetry_trace_conditions:
       - acls: ['0.0.0.0/0', '::/0']

To generate OpenTelemetry Trace information for all queries coming from ``127.0.0.1`` but only pick up the EDNS specified TraceID from all other queries:

.. code-block:: yaml

   logging:
     opentelemetry_trace_conditions:
     - acls: ['0.0.0.0/0', '::/0']
       traceid_only: true
     - acls: [127.0.0.1]

To include a TraceID in a query ``sdig`` can be used, or a modern ``dig``, specifying the EDNS option code in decimal and the payload in hex:

.. code-block:: sh

   dig +ednsopt=65500:00000102030405060708090a0b0c0d0e0fff ...

The first 4 zeroes after the colon specify the version byte and a reserved byte, followed by a 16 bytes (32 hex characters) TraceID.
Note that the EDNS option number 65500 is subject to change in the future.
To also add a parent SpanID to the EDNS value, append 8 more bytes (16 hex characters.)

Example OpenTelemetry Trace in in JSON representation
"""""""""""""""""""""""""""""""""""""""""""""""""""""

The example decoder in https://github.com/PowerDNS/pdns/blob/master/contrib/ProtobufLogger.py displays a JSON representation of the data and optionally submits the data (in Protobuf format) to an OpenTelemetry trace collector using a POST to a URL given on the command line.

An example, encoded in JSON:

.. code-block:: json

    {
      "resource_spans": [
        {
          "resource": {
            "attributes": [
              {
                "key": "service.name",
                "value": {
                  "string_value": "rec"
                }
              }
            ]
          },
          "scope_spans": [
            {
              "spans": [
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "JXJ4ddrswYQ=",
                  "parent_span_id": "AAAAAAAAAAA=",
                  "name": "RecRequest",
                  "start_time_unix_nano": "1749561792313272000",
                  "end_time_unix_nano": "1749561792750566000"
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "MQHynlz1HY8=",
                  "parent_span_id": "JXJ4ddrswYQ=",
                  "name": "ReqRecv",
                  "start_time_unix_nano": "1749561792313272000",
                  "end_time_unix_nano": "1749561792750560000",
                  "attributes": [
                    {
                      "key": "value",
                      "value": {
                        "string_value": "www.powerdns.net/A"
                      }
                    }
                  ]
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "NZy+TnYqDHA=",
                  "parent_span_id": "JXJ4ddrswYQ=",
                  "name": "PCacheCheck",
                  "start_time_unix_nano": "1749561792313363000",
                  "end_time_unix_nano": "1749561792313365000",
                  "attributes": [
                    {
                      "key": "value",
                      "value": {
                        "bool_value": false
                      }
                    }
                  ]
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "Bo/RN3dz9fs=",
                  "parent_span_id": "JXJ4ddrswYQ=",
                  "name": "SyncRes",
                  "start_time_unix_nano": "1749561792313428000",
                  "end_time_unix_nano": "1749561792750302000",
                  "attributes": [
                    {
                      "key": "value",
                      "value": {
                        "int_value": "0"
                      }
                    }
                  ]
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "xNMXyT7mWjA=",
                  "parent_span_id": "Bo/RN3dz9fs=",
                  "name": "AuthRequest",
                  "start_time_unix_nano": "1749561792313485000",
                  "end_time_unix_nano": "1749561792571098000",
                  "attributes": [
                    {
                      "key": "value",
                      "value": {
                        "string_value": "net/A"
                      }
                    },
                    {
                      "key": "value",
                      "value": {
                        "int_value": "0"
                      }
                    }
                  ]
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "p/JA/yx/qE0=",
                  "parent_span_id": "Bo/RN3dz9fs=",
                  "name": "AuthRequest",
                  "start_time_unix_nano": "1749561792572165000",
                  "end_time_unix_nano": "1749561792596116000",
                  "attributes": [
                    {
                      "key": "value",
                      "value": {
                        "string_value": "powerdns.net/A"
                      }
                    },
                    {
                      "key": "value",
                      "value": {
                        "int_value": "0"
                      }
                    }
                  ]
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "CJOTDQJtrCo=",
                  "parent_span_id": "Bo/RN3dz9fs=",
                  "name": "AuthRequest",
                  "start_time_unix_nano": "1749561792596318000",
                  "end_time_unix_nano": "1749561792610541000",
                  "attributes": [
                    {
                      "key": "value",
                      "value": {
                        "string_value": "net/DNSKEY"
                      }
                    },
                    {
                      "key": "value",
                      "value": {
                        "int_value": "0"
                      }
                    }
                  ]
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "/WEYJlz7JO4=",
                  "parent_span_id": "Bo/RN3dz9fs=",
                  "name": "AuthRequest",
                  "start_time_unix_nano": "1749561792611791000",
                  "end_time_unix_nano": "1749561792709927000",
                  "attributes": [
                    {
                      "key": "value",
                      "value": {
                        "string_value": "www.powerdns.net/A"
                      }
                    },
                    {
                      "key": "value",
                      "value": {
                        "int_value": "0"
                      }
                    }
                  ]
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "XMYoT4nXjBo=",
                  "parent_span_id": "Bo/RN3dz9fs=",
                  "name": "AuthRequest",
                  "start_time_unix_nano": "1749561792710051000",
                  "end_time_unix_nano": "1749561792730321000",
                  "attributes": [
                    {
                      "key": "value",
                      "Value": {
                        "string_value": "powerdns.net/DNSKEY"
                      }
                    },
                    {
                      "key": "value",
                      "value": {
                        "int_value": "0"
                      }
                    }
                  ]
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "wVWnDBsGOIo=",
                  "parent_span_id": "Bo/RN3dz9fs=",
                  "name": "AuthRequest",
                  "start_time_unix_nano": "1749561792730960000",
                  "end_time_unix_nano": "1749561792750073000",
                  "attributes": [
                    {
                      "key": "value",
                      "value": {
                        "string_value": "powerdns.net/A"
                      }
                    },
                    {
                      "key": "value",
                      "value": {
                        "int_value": "0"
                      }
                    }
                  ]
                },
                {
                  "trace_id": "hYxA7fc6b/0KnrVRZTZPiw==",
                  "span_id": "qllduzHSRbQ=",
                  "parent_span_id": "JXJ4ddrswYQ=",
                  "name": "AnswerSent",
                  "start_time_unix_nano": "1749561792750557000",
                  "end_time_unix_nano": "1749561792750557000"
                }
              ]
            }
          ]
        }
      ]
    }
