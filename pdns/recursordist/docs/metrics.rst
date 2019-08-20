Metrics and Statistics
======================

The PowerDNS Recursor collects many statistics about itself.

Regular Statistics Log
----------------------
Every half hour or so (configurable with :ref:`setting-statistics-interval`, the recursor outputs a line with statistics.
To force the output of statistics, send the process a SIGUSR1. A line of statistics looks like this::

    Feb 10 14:16:03 stats: 125784 questions, 13971 cache entries, 309 negative entries, 84% cache hits, outpacket/query ratio 37%, 12% throttled

This means that there are 13791 different names cached, which each may have multiple records attached to them.
There are 309 items in the negative cache, items of which it is known that don't exist and won't do so for the near future.
84% of incoming questions could be answered without any additional queries going out to the net.

The outpacket/query ratio means that on average, 0.37 packets were needed to answer a question.
Initially this ratio may be well over 100% as additional queries may be needed to actually recurse the DNS and figure out the addresses of nameservers.

Finally, 12% of queries were not performed because identical queries had gone out previously and failed, saving load on servers worldwide.

.. _metricscarbon:

Sending metrics to Graphite/Metronome over Carbon
-------------------------------------------------
For carbon/graphite/metronome, we use the following namespace.
Everything starts with 'pdns.', which is then followed by the local hostname.
Thirdly, we add 'recursor' to signify the daemon generating the metrics.
This is then rounded off with the actual name of the metric. As an example: 'pdns.ns1.recursor.questions'.

Care has been taken to make the sending of statistics as unobtrusive as possible, the daemons will not be hindered by an unreachable carbon server, timeouts or connection refused situations.

To benefit from our carbon/graphite support, either install Graphite, or use our own lightweight statistics daemon, Metronome, currently available on `GitHub <https://github.com/ahupowerdns/metronome/>`_.

To enable sending metrics, set :ref:`setting-carbon-server`, possibly :ref:`setting-carbon-interval` and possibly :ref:`setting-carbon-ourname` in the configuration.

.. warning::

  If your hostname includes dots, they will be replaced by underscores so as not to confuse the namespace.

  If you include dots in :ref:`setting-carbon-ourname`, they will **not** be replaced by underscores.
  As PowerDNS assumes you know what you are doing if you override your hostname.

Sending metrics over SNMP
-------------------------
.. versionadded:: 4.1.0

The recursor can export statistics over SNMP and send traps from :doc:`Lua <lua-scripting/index>`, provided support is compiled into the Recursor and :ref:`setting-snmp-agent` set.

MIB
^^^

.. literalinclude:: ../RECURSOR-MIB.txt

Getting Metrics from the Recursor
---------------------------------

Should Carbon not be the preferred way of receiving metric, several other techniques can be employed to retrieve metrics.

Using the Webserver
^^^^^^^^^^^^^^^^^^^
The :doc:`API <http-api/index>` exposes a statistics endpoint at :http:get:`/api/v1/servers/:server_id/statistics`.
This endpoint exports all statistics in a single JSON document.

Using ``rec_control``
^^^^^^^^^^^^^^^^^^^^^
Metrics can also be gathered on the system itself by invoking :doc:`rec_control <manpages/rec_control.1>`::

   rec_control get-all

Single statistics can also be retrieved with the ``get`` command, e.g.::

  rec_control get all-outqueries

External programs can use this technique to scrape metrics.

.. _metricnames:

Gathered Information
--------------------

These statistics are gathered.

It should be noted that answers0-1 + answers1-10 + answers10-100 + answers100-1000 + answers-slow + packetcache-hits + over-capacity-drops + policy-drops = questions.

Also note that unauthorized-tcp and unauthorized-udp packets do not end up in the 'questions' count.

all-outqueries
^^^^^^^^^^^^^^
counts the number of outgoing UDP queries since starting

answers-slow
^^^^^^^^^^^^
counts the number of queries answered after 1 second

answers0-1
^^^^^^^^^^
counts the number of queries answered within 1 millisecond

answers1-10
^^^^^^^^^^^
counts the number of queries answered within 10 milliseconds

answers10-100
^^^^^^^^^^^^^
counts the number of queries answered within 100 milliseconds

answers100-1000
^^^^^^^^^^^^^^^
counts the number of queries answered within 1 second

auth4-answers-slow
^^^^^^^^^^^^^^^^^^
counts the number of queries answered by auth4s after 1 second (4.0)

auth4-answers0-1
^^^^^^^^^^^^^^^^
counts the number of queries answered by auth4s within 1 millisecond (4.0)

auth4-answers1-10
^^^^^^^^^^^^^^^^^
counts the number of queries answered by auth4s within 10 milliseconds (4.0)

auth4-answers10-100
^^^^^^^^^^^^^^^^^^^
counts the number of queries answered by auth4s within 100 milliseconds (4.0)

auth4-answers100-1000
^^^^^^^^^^^^^^^^^^^^^
counts the number of queries answered by auth4s within 1 second (4.0)

auth6-answers-slow
^^^^^^^^^^^^^^^^^^
counts the number of queries answered by auth6s after 1 second (4.0)

auth6-answers0-1
^^^^^^^^^^^^^^^^
counts the number of queries answered by auth6s within 1 millisecond (4.0)

auth6-answers1-10
^^^^^^^^^^^^^^^^^
counts the number of queries answered by auth6s within 10 milliseconds (4.0)

auth6-answers10-100
^^^^^^^^^^^^^^^^^^^
counts the number of queries answered by  auth6s within 100 milliseconds (4.0)

auth6-answers100-1000
^^^^^^^^^^^^^^^^^^^^^
counts the number of queries answered by auth6s within 1 second (4.0)

auth-zone-queries
^^^^^^^^^^^^^^^^^
counts the number of queries to locally hosted authoritative zones (:ref:`setting-auth-zones`) since starting

cache-bytes
^^^^^^^^^^^
size of the cache in bytes

cache-entries
^^^^^^^^^^^^^
shows the number of entries in the cache

cache-hits
^^^^^^^^^^
counts the number of cache hits since starting, this does **not** include hits that got answered from the packet-cache

cache-misses
^^^^^^^^^^^^
counts the number of cache misses since starting

case-mismatches
^^^^^^^^^^^^^^^
counts the number of mismatches in character   case since starting

chain-resends
^^^^^^^^^^^^^
number of queries chained to existing outstanding   query

client-parse-errors
^^^^^^^^^^^^^^^^^^^
counts number of client packets that could   not be parsed

concurrent-queries
^^^^^^^^^^^^^^^^^^
shows the number of MThreads currently   running

cpu-msec-thread-n
^^^^^^^^^^^^^^^^^
shows the number of milliseconds spent in thread n. Available since 4.1.12.

dlg-only-drops
^^^^^^^^^^^^^^
number of records dropped because of :ref:`setting-delegation-only` setting

dnssec-authentic-data-queries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2

number of queries received with the AD bit set

dnssec-check-disabled-queries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2

number of queries received with the CD bit set

dnssec-queries
^^^^^^^^^^^^^^
number of queries received with the DO bit set

dnssec-result-bogus
^^^^^^^^^^^^^^^^^^^
number of DNSSEC validations that had the   Bogus state

dnssec-result-indeterminate
^^^^^^^^^^^^^^^^^^^^^^^^^^^
number of DNSSEC validations that   had the Indeterminate state

dnssec-result-insecure
^^^^^^^^^^^^^^^^^^^^^^
number of DNSSEC validations that had the   Insecure state

dnssec-result-nta
^^^^^^^^^^^^^^^^^
number of DNSSEC validations that had the NTA   (negative trust anchor) state

dnssec-result-secure
^^^^^^^^^^^^^^^^^^^^
number of DNSSEC validations that had the   Secure state

dnssec-validations
^^^^^^^^^^^^^^^^^^
number of DNSSEC validations performed

dont-outqueries
^^^^^^^^^^^^^^^
number of outgoing queries dropped because of   :ref:`setting-dont-query` setting (since 3.3)

ecs-queries
^^^^^^^^^^^
number of outgoing queries adorned with an EDNS Client Subnet option (since 4.1)

ecs-responses
^^^^^^^^^^^^^
number of responses received from authoritative servers with an EDNS Client Subnet option we used (since 4.1)

ecs-v4-response-bits-*
^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

number of responses received from authoritative servers with an IPv4 EDNS Client Subnet option we used, of this subnet size (1 to 32).

ecs-v6-response-bits-*
^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

number of responses received from authoritative servers with an IPv6 EDNS Client Subnet option we used, of this subnet size (1 to 128).

edns-ping-matches
^^^^^^^^^^^^^^^^^
number of servers that sent a valid EDNS PING   response

edns-ping-mismatches
^^^^^^^^^^^^^^^^^^^^
number of servers that sent an invalid EDNS   PING response

failed-host-entries
^^^^^^^^^^^^^^^^^^^
number of servers that failed to resolve

ignored-packets
^^^^^^^^^^^^^^^
counts the number of non-query packets received   on server sockets that should only get query packets

ipv6-outqueries
^^^^^^^^^^^^^^^
number of outgoing queries over IPv6

ipv6-questions
^^^^^^^^^^^^^^
counts all end-user initiated queries with the RD   bit set, received over IPv6 UDP

malloc-bytes
^^^^^^^^^^^^
returns the number of bytes allocated by the process (broken, always returns 0)

max-cache-entries
^^^^^^^^^^^^^^^^^
currently configured maximum number of cache entries

max-packetcache-entries
^^^^^^^^^^^^^^^^^^^^^^^
currently configured maximum number of packet cache entries

max-mthread-stack
^^^^^^^^^^^^^^^^^
maximum amount of thread stack ever used

negcache-entries
^^^^^^^^^^^^^^^^
shows the number of entries in the negative   answer cache

no-packet-error
^^^^^^^^^^^^^^^
number of erroneous received packets

noedns-outqueries
^^^^^^^^^^^^^^^^^
number of queries sent out without EDNS

noerror-answers
^^^^^^^^^^^^^^^
counts the number of times it answered NOERROR   since starting

noping-outqueries
^^^^^^^^^^^^^^^^^
number of queries sent out without ENDS PING

nsset-invalidations
^^^^^^^^^^^^^^^^^^^
number of times an nsset was dropped because   it no longer worked

nsspeeds-entries
^^^^^^^^^^^^^^^^
shows the number of entries in the NS speeds   map

nxdomain-answers
^^^^^^^^^^^^^^^^
counts the number of times it answered NXDOMAIN   since starting

outgoing-timeouts
^^^^^^^^^^^^^^^^^
counts the number of timeouts on outgoing UDP   queries since starting

outgoing4-timeouts
^^^^^^^^^^^^^^^^^^
counts the number of timeouts on outgoing UDP   IPv4 queries since starting (since 4.0)

outgoing6-timeouts
^^^^^^^^^^^^^^^^^^
counts the number of timeouts on outgoing UDP   IPv6 queries since starting (since 4.0)

over-capacity-drops
^^^^^^^^^^^^^^^^^^^
questions dropped because over maximum   concurrent query limit (since 3.2)

packetcache-bytes
^^^^^^^^^^^^^^^^^
size of the packet cache in bytes (since   3.3.1)

packetcache-entries
^^^^^^^^^^^^^^^^^^^
size of packet cache (since 3.2)

packetcache-hits
^^^^^^^^^^^^^^^^
packet cache hits (since 3.2)

packetcache-misses
^^^^^^^^^^^^^^^^^^
packet cache misses (since 3.2)

policy-drops
^^^^^^^^^^^^
packets dropped because of (Lua) policy decision

policy-result-noaction
^^^^^^^^^^^^^^^^^^^^^^
packets that were not actioned upon by   the RPZ/filter engine

policy-result-drop
^^^^^^^^^^^^^^^^^^
packets that were dropped by the RPZ/filter   engine

policy-result-nxdomain
^^^^^^^^^^^^^^^^^^^^^^
packets that were replied to with   NXDOMAIN by the RPZ/filter engine

policy-result-nodata
^^^^^^^^^^^^^^^^^^^^
packets that were replied to with no data   by the RPZ/filter engine

policy-result-truncate
^^^^^^^^^^^^^^^^^^^^^^
packets that were forced to TCP by the   RPZ/filter engine

policy-result-custom
^^^^^^^^^^^^^^^^^^^^
packets that were sent a custom answer by   the RPZ/filter engine

qa-latency
^^^^^^^^^^
shows the current latency average, in microseconds,   exponentially weighted over past 'latency-statistic-size' packets

query-pipe-full-drops
^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2

questions dropped because the query distribution pipe was full

questions
^^^^^^^^^
counts all end-user initiated queries with the RD bit   set

rebalanced-queries
^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.12

number of queries balanced to a different worker thread because the first selected one was above the target load configured with 'distribution-load-factor'

resource-limits
^^^^^^^^^^^^^^^
counts number of queries that could not be   performed because of resource limits

security-status
^^^^^^^^^^^^^^^
security status based on :ref:`securitypolling`

server-parse-errors
^^^^^^^^^^^^^^^^^^^
counts number of server replied packets that   could not be parsed

servfail-answers
^^^^^^^^^^^^^^^^
counts the number of times it answered SERVFAIL   since starting

spoof-prevents
^^^^^^^^^^^^^^
number of times PowerDNS considered itself   spoofed, and dropped the data

sys-msec
^^^^^^^^
number of CPU milliseconds spent in 'system' mode

tcp-client-overflow
^^^^^^^^^^^^^^^^^^^
number of times an IP address was denied TCP   access because it already had too many connections

tcp-clients
^^^^^^^^^^^
counts the number of currently active TCP/IP clients

tcp-outqueries
^^^^^^^^^^^^^^
counts the number of outgoing TCP queries since   starting

tcp-questions
^^^^^^^^^^^^^
counts all incoming TCP queries (since starting)

throttle-entries
^^^^^^^^^^^^^^^^
shows the number of entries in the throttle map

throttled-out
^^^^^^^^^^^^^
counts the number of throttled outgoing UDP   queries since starting

throttled-outqueries
^^^^^^^^^^^^^^^^^^^^
idem to throttled-out

too-old-drops
^^^^^^^^^^^^^
questions dropped that were too old

truncated-drops
^^^^^^^^^^^^^^^
.. versionadded:: 4.2

questions dropped because they were larger than 512 bytes

empty-queries
^^^^^^^^^^^^^
.. versionadded:: 4.2

questions dropped because they had a QD count of 0

unauthorized-tcp
^^^^^^^^^^^^^^^^
number of TCP questions denied because of   allow-from restrictions

unauthorized-udp
^^^^^^^^^^^^^^^^
number of UDP questions denied because of   allow-from restrictions

unexpected-packets
^^^^^^^^^^^^^^^^^^
number of answers from remote servers that   were unexpected (might point to spoofing)

unreachables
^^^^^^^^^^^^
number of times nameservers were unreachable since   starting

uptime
^^^^^^
number of seconds process has been running (since 3.1.5)

user-msec
^^^^^^^^^
number of CPU milliseconds spent in 'user' mode

.. _stat-x-our-latency:

variable-responses
^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2

Responses that were marked as 'variable'. This could be because of EDNS
Client Subnet or Lua rules that indicate this variable status (dependent on
time or who is asking, for example).

x-our-latency
^^^^^^^^^^^^^
.. versionadded:: 4.1
  Not yet proven to be reliable

PowerDNS measures per query how much time has been spent waiting on authoritative servers.
In addition, the Recursor measures the total amount of time needed to answer a question.
The difference between these two durations is a measure of how much time was spent within PowerDNS.
This metric is the average of that difference, in microseconds.

x-ourtime0-1
^^^^^^^^^^^^
.. versionadded:: 4.1
  Not yet proven to be reliable

Counts responses where between 0 and 1 milliseconds was spent within the Recursor.
See :ref:`stat-x-our-latency` for further details.

x-ourtime1-2
^^^^^^^^^^^^
.. versionadded:: 4.1
  Not yet proven to be reliable

Counts responses where between 1 and 2 milliseconds was spent within the Recursor.
See :ref:`stat-x-our-latency` for further details.

x-ourtime2-4
^^^^^^^^^^^^
.. versionadded:: 4.1
  Not yet proven to be reliable

Counts responses where between 2 and 4 milliseconds was spent within the Recursor. Since 4.1.
See :ref:`stat-x-our-latency` for further details.

x-ourtime4-8
^^^^^^^^^^^^
.. versionadded:: 4.1
  Not yet proven to be reliable

Counts responses where between 4 and 8 milliseconds was spent within the Recursor.
See :ref:`stat-x-our-latency` for further details.

x-ourtime8-16
^^^^^^^^^^^^^
.. versionadded:: 4.1
  Not yet proven to be reliable

Counts responses where between 8 and 16 milliseconds was spent within the Recursor.
See :ref:`stat-x-our-latency` for further details.

x-ourtime16-32
^^^^^^^^^^^^^^
.. versionadded:: 4.1
  Not yet proven to be reliable

Counts responses where between 16 and 32 milliseconds was spent within the Recursor.
See :ref:`stat-x-our-latency` for further details.

x-ourtime-slow
^^^^^^^^^^^^^^
.. versionadded:: 4.1
  Not yet proven to be reliable

Counts responses where more than 32 milliseconds was spent within the Recursor.
See :ref:`stat-x-our-latency` for further details.
