Statistics
==========

dnsdist keeps statistics on the queries is receives and send out. They can be accessed in different ways:

- via the console (see :ref:`Console`), using :func:`dumpStats` for the general ones,
  :func:`showServers()` for the ones related to the backends, :func:`showBinds()` for the frontends,
  `getPool("pool name"):getCache():printStats()` for the ones related to a specific cache and so on
- via the internal webserver (see :doc:`../guides/webserver`)
- via Carbon / Graphite / Metronome export (see :doc:`../guides/carbon`)
- via SNMP (see :doc:`../advanced/snmp`)

acl-drops
---------
The number of packets dropped bacause of the :doc:`ACL <advanced/acl>`.

cache-hits
----------
Number of times an answer was retrieved from :doc:`cache <guides/cache>`.

cache-misses
------------
Number of times an answer was not found in the :doc:`cache <guides/cache>`.

cpu-sys-msec
------------
Milliseconds spent by :program:`dnsdist` in the "system" state.

cpu-user-msec
-------------
Milliseconds spent by :program:`dnsdist` in the "user" state.

downstream-send-errors
----------------------
Number of errors when sending a query to a backend.

downstream-timeouts
-------------------
Number of queries not answer in time by a backend.

dyn-block-nmg-size
------------------
Number of dynamic blocks entries.

dyn-blocked
-----------
Number of queries dropped because of a dynamic block.

empty-queries
-------------
Number of empty queries received from clients.

fd-usage
--------
Number of currently used file descriptors.

latency-avg100
--------------
Average response latency of the last 100 packets.

latency-avg1000
---------------
Average response latency of the last 1000 packets.

latency-avg10000
----------------
Average response latency of the last 10000 packets.

latency-avg1000000
------------------
Average response latency of the last 1000000 packets.

latency-slow
------------
Number of queries answered in more than 1 second.

latency0-1
----------
Number of queries answered in less than 1 ms.

latency1-10
-----------
Number of queries answered in 1-10 ms.

latency10-50
------------
Number of queries answered in 10-50 ms.

latency50-100
-------------
Number of queries answered in 50-100 ms.

latency100-1000
---------------
Number of queries answered in 100-1000 ms.

no-policy
---------
Number of queries dropped because no server was available.

noncompliant-queries
--------------------
Number of queries dropped as non-compliant.

noncompliant-responses
----------------------
Number of answers from a backend dropped as non-compliant.

queries
-------
Number of received queries.

rdqueries
---------
Number of received queries with the recursion desired bit set.

real-memory-usage
-----------------
Current memory usage.

responses
---------
Number of responses received from backends.

rule-drop
---------
Number of queries dropped because of a rule.

rule-nxdomain
-------------
Number of NXDomain answers returned because of a rule.

rule-refused
------------
Number of Refused answers returned because of a rule.

self-answered
-------------
Number of self-answered responses.

servfail-responses
------------------
Number of servfail answers received from backends.

trunc-failures
--------------
Number of errors encountered while truncating an answer.

uptime
------
Uptime of the dnsdist process, in seconds.

