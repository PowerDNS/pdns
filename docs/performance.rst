Performance and Tuning
======================

In general, best performance is achieved on recent Linux kernels with
the bindbackend, or if something more database-like is preferred,
the LMDB backend. Meanwhile many of the largest PowerDNS installations are
based on PostgreSQL or MySQL.

Database servers can require configuration to achieve decent
performance. It is especially worth noting that several vendors ship
PostgreSQL with a slow default configuration.

.. warning::
  When deploying (large scale) IPv6, please be aware some
  Linux distributions leave IPv6 routing cache tables at very small
  default values. Please check and if necessary raise
  ``sysctl net.ipv6.route.max_size``.

Performance related settings
----------------------------

When PowerDNS starts up it creates a number of threads to listen for
packets. This is configurable with the
:ref:`setting-receiver-threads` setting which
defines how many sockets will be opened by the powerdns process. In
versions of linux before kernel 3.9 having too many receiver threads set
up resulted in decreased performance due to socket contention between
multiple CPUs - the typical sweet spot was 3 or 4. For optimal
performance on kernel 3.9 and following with
:ref:`setting-reuseport` enabled you'll typically want
a receiver thread for each core on your box if backend
latency/performance is not an issue and you want top performance.

Different backends will have different characteristics - some will want
to have more parallel instances than others. In general, if your backend
is latency bound, like most relational databases are, it pays to open
more backends.

This is done with the
:ref:`setting-distributor-threads` setting
which says how many distributors will be opened for each receiver
thread. Of special importance is the choice between 1 or more backends.
In case of only 1 thread, PowerDNS reverts to unthreaded operation which
may be a lot faster, depending on your operating system and
architecture.

Other very important settings are
:ref:`setting-cache-ttl`. PowerDNS caches entire
packets it sends out so as to save the time to query backends to
assemble all data. The default setting of 20 seconds may be low for high
traffic sites, a value of 60 seconds rarely leads to problems. Please be
aware that if any TTL in the answer is shorter than this setting, the
packet cache will respect the answer's shortest TTL.

Some PowerDNS operators set cache-ttl to many hours or even days, and
use :ref:`pdns_control purge <running-pdnscontrol>`  to
selectively or globally notify PowerDNS of changes made in the backend.
Also look at the :ref:`query-cache` described in this
chapter. It may materially improve your performance.

To determine if PowerDNS is unable to keep up with packets, determine
the value of the :ref:`stat-qsize-q` variable. This represents the number of
packets waiting for database attention. During normal operations the
queue should be small.
This number is a total over all receiver threads.

The :ref:`setting-max-queue-length` and :ref:`setting-overload-queue-length` settings determine how PowerDNS deals with growing queues.
If the queue for a single receiver thread (and its associated distributor threads) grows beyond the ``overload`` number, queries are answered only from the packet cache so the database can hopefully recover.
If we reach the ``max`` number, we consider the situation hopeless and respawn the server process.

The value of :ref:`setting-queue-limit` should be set to only keep queries in
queue for as long as someone would be interested in knowing the answer. Many
resolvers will query other name servers for the zone quite aggressively.

Logging truly kills performance as answering a question from the cache
is an order of magnitude less work than logging a line about it. Busy
sites will prefer to turn :ref:`setting-log-dns-details` off.

.. _packet-cache:

Packet Cache
------------

PowerDNS by default uses the 'Packet Cache' to recognise identical
questions and supply them with identical answers, without any further
processing. The default time to live is 20 seconds and can be changed by
setting ``cache-ttl``. It has been observed that the utility of the
packet cache increases with the load on your nameserver.

Not all backends may benefit from the packet cache. If your backend is
memory based and does not lead to context switches, the packet cache may
actually hurt performance.

.. _query-cache:

Query Cache
-----------

Besides entire packets, PowerDNS can also cache individual backend
queries. Each DNS query leads to a number of backend queries, the most
obvious additional backend query is the check for a possible CNAME. So,
when a query comes in for the 'A' record for 'www.powerdns.com',
PowerDNS must first check for a CNAME for 'www.powerdns.com'.

The Query Cache caches these backend queries, many of which are quite
repetitive. The maximum number of entries in the cache is controlled by
the ``max-cache-entries`` setting. Before 4.1 this setting also controls
the maximum number of entries in the packet cache.

Most gain is made from caching negative entries, ie, queries that have
no answer. As these take little memory to store and are typically not a
real problem in terms of speed-of-propagation, the default TTL for
negative queries is a rather high 60 seconds.

This only is a problem when first doing a query for a record, adding it,
and immediately doing a query for that record again. It may then take up
to 60 seconds to appear. Changes to existing records however do not fall
under the negative query ttl
(:ref:`setting-negquery-cache-ttl`), but under
the generic :ref:`setting-query-cache-ttl` which
defaults to 20 seconds.

The default values should work fine for many sites. When tuning, keep in
mind that the Query Cache mostly saves database access but that the
Packet Cache also saves a lot of CPU because zero internal processing is
done when answering a question from the Packet Cache.

Caches & Memory Allocations & glibc
-----------------------------------

Managing the two caches described above involves a lot of memory management, that is handled by ``malloc`` in your libc.
To avoid contention between threads, the allocator in glibc separates memory into separate arenas, sometimes even hundreds of them.
This avoids locking, but it may cause massive memory fragmentation, that could make PowerDNS take `an order of magnitude more memory <https://sourceware.org/bugzilla/show_bug.cgi?id=11261>`_ in some situations.

If you suspect this is happening on your setup, you can consider lowering ``MALLOC_ARENA_MAX`` to a small number.
Several users have reported that ``4`` works well for them.
Via ``systemctl edit pdns`` you can put ``Environment=MALLOC_ARENA_MAX=4`` in your pdns unit file to enable this tweak.

Note that `newer glibc versions replace MALLOC_ARENA_MAX with a different setting syntax <https://www.gnu.org/software/libc/manual/html_node/Tunables.html#Tunables>`__.
The new syntax is ``GLIBC_TUNABLES=glibc.malloc.arena_max=4``, please check which syntax is valid for your glibc version (it is quite likely that both syntaxes will work).

Performance Monitoring
----------------------

A number of counters and variables are set during PowerDNS Authoritative
Server operation.

.. _counters:
.. _metricnames:

Counters
~~~~~~~~

All counters that show the "number of X" count since the last startup of the daemon.

.. _stat-corrupt-packets:

corrupt-packets
^^^^^^^^^^^^^^^
Number of corrupt packets received

.. _stat-deferred-cache-inserts:

deferred-cache-inserts
^^^^^^^^^^^^^^^^^^^^^^
Number of cache inserts that were deferred because of maintenance

.. _stat-deferred-cache-lookup:

deferred-cache-lookup
^^^^^^^^^^^^^^^^^^^^^
Number of cache lookups that were deferred because of maintenance

.. _stat-deferred-packetcache-inserts:

deferred-packetcache-inserts
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Number of packet cache inserts that were deferred because of maintenance

.. _stat-deferred-packetcache-lookup:

deferred-packetcache-lookup
^^^^^^^^^^^^^^^^^^^^^^^^^^^
Number of packet cache lookups that were deferred because of maintenance

.. _stat-dnsupdate-answers:

dnsupdate-answers
^^^^^^^^^^^^^^^^^
Number of DNS update packets successfully answered

.. _stat-dnsupdate-changes:

dnsupdate-changes
^^^^^^^^^^^^^^^^^
Total number of changes to records from DNS update

.. _stat-dnsupdate-queries:

dnsupdate-queries
^^^^^^^^^^^^^^^^^
Number of DNS update packets received

.. _stat-dnsupdate-refused:

dnsupdate-refused
^^^^^^^^^^^^^^^^^
Number of DNS update packets that were refused

.. _stat-incoming-notifications:

incoming-notifications
^^^^^^^^^^^^^^^^^^^^^^
Number of NOTIFY packets that were received

.. _stat-key-cache-size:

key-cache-size
^^^^^^^^^^^^^^
Number of entries in the key cache

.. _stat-latency:

latency
^^^^^^^
Average number of microseconds a packet spends within PowerDNS

.. _stat-meta-cache-size:

meta-cache-size
^^^^^^^^^^^^^^^
Number of entries in the metadata cache

.. _stat-open-tcp-connections:

open-tcp-connections
^^^^^^^^^^^^^^^^^^^^
Number of currently open TCP connections

.. _stat-overload-drops:

overload-drops
^^^^^^^^^^^^^^
Number of questions dropped because backends overloaded (backends are overloaded if they have more outstanding queries than the value of :ref:`setting-overload-queue-length`)

.. _stat-packetcache-hit:

packetcache-hit
^^^^^^^^^^^^^^^
Number of packets which were answered out of the cache

.. _stat-packetcache-miss:

packetcache-miss
^^^^^^^^^^^^^^^^
Number of times a packet could not be answered out of the cache

.. _stat-packetcache-size:

packetcache-size
^^^^^^^^^^^^^^^^
Amount of packets in the packetcache

.. _stat-qsize-q:

qsize-q
^^^^^^^
Number of packets waiting for database attention, only available if :ref:`setting-distributor-threads` > 1

.. _stat-query-cache-hit:

query-cache-hit
^^^^^^^^^^^^^^^
Number of hits on the :ref:`query-cache`

.. _stat-query-cache-miss:

query-cache-miss
^^^^^^^^^^^^^^^^
Number of misses on the :ref:`query-cache`

.. _stat-query-cache-size:

query-cache-size
^^^^^^^^^^^^^^^^
Number of entries in the query cache

.. _stat-rd-queries:

rd-queries
^^^^^^^^^^
Number of packets sent by clients requesting recursion (regardless of if we'll be providing them with recursion).

.. _stat-receive-latency:

receive-latency
^^^^^^^^^^^^^^^
Average number of microseconds needed to receive a query

.. _stat-recursing-answers:

recursing-answers
^^^^^^^^^^^^^^^^^
Number of packets we supplied an answer to after recursive processing

.. _stat-recursing-questions:

recursing-questions
^^^^^^^^^^^^^^^^^^^
Number of packets we performed recursive processing for.

.. _stat-recursion-unanswered:

recursion-unanswered
^^^^^^^^^^^^^^^^^^^^
Number of packets we sent to our recursor, but did not get a timely answer for.

.. _stat-security-status:

security-status
^^^^^^^^^^^^^^^
Security status based on :ref:`securitypolling`.

.. _stat-send-latency:

send-latency
^^^^^^^^^^^^
Average number of microseconds needed to send the answer

.. _stat-servfail-packets:

servfail-packets
^^^^^^^^^^^^^^^^
Amount of packets that could not be answered due to database problems

.. _stat-signature-cache-size:

signature-cache-size
^^^^^^^^^^^^^^^^^^^^
Number of entries in the signature cache

.. _stat-signatures:

signatures
^^^^^^^^^^
Number of DNSSEC signatures created

.. _stat-sys-msec:

sys-msec
^^^^^^^^
Number of CPU milliseconds sent in system time

.. _stat-tcp-answers-bytes:

tcp-answers-bytes
^^^^^^^^^^^^^^^^^
Total number of answer bytes sent over TCP

.. _stat-tcp-answers:

tcp-answers
^^^^^^^^^^^
Number of answers sent out over TCP

.. _stat-tcp-queries:

tcp-queries
^^^^^^^^^^^
Number of questions received over TCP

.. _stat-tcp4-answers-bytes:

tcp4-answers-bytes
^^^^^^^^^^^^^^^^^^
Total number of answer bytes sent over TCPv4

.. _stat-tcp4-answers:

tcp4-answers
^^^^^^^^^^^^^^^^
Number of answers sent out over TCPv4

.. _stat-tcp4-queries:

tcp4-queries
^^^^^^^^^^^^
Number of questions received over TCPv4

.. _stat-tcp6-answers-bytes:

tcp6-answers-bytes
^^^^^^^^^^^^^^^^^^
Total number of answer bytes sent over TCPv6

.. _stat-tcp6-answers:

tcp6-answers
^^^^^^^^^^^^
Number of answers sent out over TCPv6

.. _stat-tcp6-queries:

tcp6-queries
^^^^^^^^^^^^
Number of questions received over TCPv6

.. _stat-timedout-packets:

timedout-packets
^^^^^^^^^^^^^^^^
Amount of packets that were dropped because they had to wait too long internally

.. _stat-udp-answers-bytes:

udp-answers-bytes
^^^^^^^^^^^^^^^^^
Total number of answer bytes sent over UDP

.. _stat-udp-answers:

udp-answers
^^^^^^^^^^^
Number of answers sent out over UDP

.. _stat-udp-do-queries:

udp-do-queries
^^^^^^^^^^^^^^
Number of queries received with the DO (DNSSEC OK) bit set

.. _stat-udp-in-csum-errors:

udp-in-csum-errors
^^^^^^^^^^^^^^^^^^
Number of UDP packets received with an invalid checksum

.. _stat-udp-in-errors:

udp-in-errors
^^^^^^^^^^^^^
Number of packets received faster than the OS could process them

.. _stat-udp-noport-errors:

udp-noport-errors
^^^^^^^^^^^^^^^^^
Number of UDP packets where an ICMP response was received that the remote port was not listening

.. _stat-udp-queries:

udp-queries
^^^^^^^^^^^
Number of questions received over UDP

.. _stat-udp-recvbuf-errors:

udp-recvbuf-errors
^^^^^^^^^^^^^^^^^^
Number of errors caused in the UDP receive buffer

.. _stat-udp-sndbuf-errors:

udp-sndbuf-errors
^^^^^^^^^^^^^^^^^
Number of errors caused in the UDP send buffer

.. _stat-udp4-answers-bytes:

udp4-answers-bytes
^^^^^^^^^^^^^^^^^^
Total number of answer bytes sent over UDPv4

.. _stat-udp4-answers:

udp4-answers
^^^^^^^^^^^^
Number of answers sent out over UDPv4

.. _stat-udp4-queries:

udp4-queries
^^^^^^^^^^^^
Number of questions received over UDPv4

.. _stat-udp6-answers-bytes:

udp6-answers-bytes
^^^^^^^^^^^^^^^^^^
Total number of answer bytes sent over UDPv6

.. _stat-udp6-answers:

udp6-answers
^^^^^^^^^^^^
Number of answers sent out over UDPv6

.. _stat-udp6-in-csum-errors:

udp6-in-csum-errors
^^^^^^^^^^^^^^^^^^^
Number of IPv6 UDP packets received with an invalid checksum

.. _stat-udp6-in-errors:

udp6-in-errors
^^^^^^^^^^^^^^
Number of IPv6 UDP packets received faster than the OS could process them

.. _stat-udp6-noport-errors:

udp6-noport-errors
^^^^^^^^^^^^^^^^^^
Number of IPv6 UDP packets where an ICMP response was received that the remote port was not listening

.. _stat-udp6-queries:

udp6-queries
^^^^^^^^^^^^
Number of questions received over UDPv6

.. _stat-udp6-recvbuf-errors:

udp6-recvbuf-errors
^^^^^^^^^^^^^^^^^^^
Number of errors caused in the IPv6 UDP receive buffer

.. _stat-udp6-sndbuf-errors:

udp6-sndbuf-errors
^^^^^^^^^^^^^^^^^^
Number of errors caused in the IPv6 UDP send buffer

.. _stat-uptime:

uptime
^^^^^^
Uptime in seconds of the daemon

.. _stat-user-msec:

user-msec
^^^^^^^^^
Number of milliseconds spend in CPU 'user' time

Ring buffers
~~~~~~~~~~~~

Besides counters, PowerDNS also maintains the ringbuffers. A ringbuffer
records events, each new event gets a place in the buffer until it is
full. When full, earlier entries get overwritten, hence the name 'ring'.

By counting the entries in the buffer, statistics can be generated.
These statistics can currently only be viewed using the webserver and
are in fact not even collected without the webserver running.

The following ringbuffers are available:

-  **logmessages**: All messages logged
-  **noerror-queries**: Queries for existing records but for a type we
   don't have. Queries for, say, the AAAA record of a domain, when only
   an A is available. Queries are listed in the following format:
   name/type. So an AAAA query for pdns.powerdns.com looks like
   pdns.powerdns.com/AAAA.
-  **nxdomain-queries**: Queries for non-existing records within
   existing domains. If PowerDNS knows it is authoritative over a
   domain, and it sees a question for a record in that domain that does
   not exist, it is able to send out an authoritative 'no such domain'
   message. Indicates that hosts are trying to connect to services
   really not in your zone.
-  **udp-queries**: All UDP queries seen.
-  **remotes**: Remote server IP addresses. Number of hosts querying
   PowerDNS. Be aware that UDP is anonymous - person A can send queries
   that appear to be coming from person B.
-  **remote-corrupts**: Remotes sending corrupt packets. Hosts sending
   PowerDNS broken packets, possibly meant to disrupt service. Be aware
   that UDP is anonymous - person A can send queries that appear to be
   coming from person B.
-  **remote-unauth**: Remotes querying domains for which we are not
   authoritative. It may happen that there are misconfigured hosts on
   the internet which are configured to think that a PowerDNS
   installation is in fact a resolving nameserver. These hosts will not
   get useful answers from PowerDNS. This buffer lists hosts sending
   queries for domains which PowerDNS does not know about.
-  **servfail-queries**: Queries that could not be answered due to
   backend errors. For one reason or another, a backend may be unable to
   extract answers for a certain domain from its storage. This may be
   due to a corrupt database or to inconsistent data. When this happens,
   PowerDNS sends out a 'servfail' packet indicating that it was unable
   to answer the question. This buffer shows which queries have been
   causing servfails.
-  **unauth-queries**: Queries for domains that we are not authoritative
   for. If a domain is delegated to a PowerDNS instance, but the backend
   is not made aware of this fact, questions come in for which no answer
   is available, nor is the authority. Use this ringbuffer to spot such
   queries.

.. _metricscarbon:

Sending metrics to Graphite/Metronome over Carbon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For carbon/graphite/metronome, we use the following namespace.
Everything starts with 'pdns.', which is then followed by the local hostname.
Thirdly, we add 'auth' to signify the daemon generating the metrics.
This is then rounded off with the actual name of the metric. As an example: 'pdns.ns1.auth.questions'.

Care has been taken to make the sending of statistics as unobtrusive as possible, the daemons will not be hindered by an unreachable carbon server, timeouts or connection refused situations.

To benefit from our carbon/graphite support, either install Graphite, or use our own lightweight statistics daemon, Metronome, currently available on `GitHub <https://github.com/ahupowerdns/metronome/>`_.

To enable sending metrics, set :ref:`setting-carbon-server`, possibly :ref:`setting-carbon-interval` and possibly :ref:`setting-carbon-ourname` in the configuration.

.. warning::

  If your hostname includes dots, they will be replaced by underscores so as not to confuse the namespace.

  If you include dots in :ref:`setting-carbon-ourname`, they will **not** be replaced by underscores.
  As PowerDNS assumes you know what you are doing if you override your hostname.
