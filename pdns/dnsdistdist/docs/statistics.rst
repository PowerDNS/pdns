Statistics
==========

dnsdist keeps statistics on the queries is receives and send out.

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
Miliseconds spent by :program:`dnsdist` in the "system" state.

cpu-user-msec
-------------
Miliseconds spent by :program:`dnsdist` in the "user" state.

downstream-send-errors
----------------------

downstream-timeouts
-------------------

dyn-block-nmg-size
------------------

dyn-blocked
-----------

empty-queries
-------------

fd-usage
--------

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

latency0-1
----------

latency1-10
-----------

latency10-50
------------

latency50-100
-------------

latency100-1000
---------------

no-policy
---------

noncompliant-queries
--------------------

noncompliant-responses
----------------------

queries
-------
Number of received queries.

rdqueries
---------
Number of received queries with the recursion desired bit set.

real-memory-usage
-----------------

responses
---------

rule-drop
---------

rule-nxdomain
-------------

rule-refused
------------

self-answered
-------------

servfail-responses
------------------

trunc-failures
--------------

uptime
------

