Metrics and Statistics
======================

The PowerDNS Recursor collects many statistics about itself.

Regular Statistics Log
----------------------
Every half hour or so (configurable with :ref:`setting-yaml-logging.statistics_interval`, the recursor outputs a line with statistics.
To force the output of statistics, send the process SIGUSR1. A line of statistics looks like this::

  stats: 346362 questions, 7388 cache entries, 1773 negative entries, 18% cache hits
  stats: cache contended/acquired 1583/56041728 = 0.00282468%
  stats: throttle map: 3, ns speeds: 1487, failed ns: 15, ednsmap: 1363
  stats: outpacket/query ratio 54%, 0% throttled, 0 no-delegation drops
  stats: 217 outgoing tcp connections, 0 queries running, 9155 outgoing timeouts
  stats: 4536 packet cache entries, 82% packet cache hits
  stats: thread 0 has been distributed 175728 queries
  stats: thread 1 has been distributed 169484 queries
  stats: 1 qps (average over 1800 seconds)

This means that in total 346362 queries were received and there are 7388 different name/type combinations in the record cache, each entry may have multiple records attached to it.

There are 1773 items in the negative cache, items of which it is known that don't exist and won't do so for the near future.
18% of incoming questions not handled by the packets cache could be answered without any additional queries going out to the net.
The record cache was consulted or modified 56041728 times, and 1583 of those accesses caused lock contention.

Next a line with the sizes of maps that can be consulted by :program:`rec_control` is printed.

The outpacket/query ratio means that on average, 0.54 packets were needed to answer a question.
This ratio can be greater than 100% since additional queries could be needed to actually recurse the DNS and figure out the addresses of nameservers.

0% of queries were not performed because identical queries had gone out previously and failed, saving load on servers worldwide.
217 outgoing tcp connections were done, there were 0 queries running at the moment and 9155 queries to authoritative servers saw timeouts.

The packets cache had 4536 entries and 82% of queries were served from it.
The workload of the worker queries was 175728 and 169484 respectively.
Finally, measured in the last half hour, an average of 1 qps was performed.

Multi-threading and metrics
---------------------------
Some metrics are collected in thread-local variables, and an aggregate values is computed to report.
Other statistics are recorded in global memory and each thread updates the one instance, taking proper precautions to make sure consistency is maintained.
The only exception are the ``cpu-msec-thread-n`` metrics, which report per-thread data.

.. _metricscarbon:


Sending metrics to Graphite/Metronome over Carbon
-------------------------------------------------
For carbon/graphite/metronome, we use the following namespace.
Everything starts with 'pdns.', which is then followed by the local hostname.
Thirdly, we add 'recursor' to signify the daemon generating the metrics.
This is then rounded off with the actual name of the metric. As an example: 'pdns.ns1.recursor.questions'.

Care has been taken to make the sending of statistics as unobtrusive as possible, the daemons will not be hindered by an unreachable carbon server, timeouts or connection refused situations.

To benefit from our carbon/graphite support, either install Graphite, or use our own lightweight statistics daemon, Metronome, currently available on `GitHub <https://github.com/ahupowerdns/metronome/>`_.

To enable sending metrics, set :ref:`setting-yaml-carbon.server`, possibly :ref:`setting-yaml-carbon.interval` and possibly :ref:`setting-yaml-carbon.ourname` in the configuration.

.. warning::

  If your hostname includes dots, they will be replaced by underscores so as not to confuse the namespace.

  If you include dots in :ref:`setting-yaml-carbon.ourname`, they will **not** be replaced by underscores.
  As PowerDNS assumes you know what you are doing if you override your hostname.


Getting Metrics from the Recursor
---------------------------------

Should Carbon not be the preferred way of receiving metrics, several other techniques can be employed to retrieve them.

Using the Webserver
^^^^^^^^^^^^^^^^^^^
The :doc:`API <http-api/index>` exposes a statistics endpoint at

.. http:get:: /api/v1/servers/:server_id/statistics

This endpoint exports all statistics in a single JSON document.

Using ``rec_control``
^^^^^^^^^^^^^^^^^^^^^
Metrics can also be gathered on the system itself by invoking :doc:`rec_control <manpages/rec_control.1>`::

   rec_control get-all

Single statistics can also be retrieved with the ``get`` command, e.g.::

  rec_control get all-outqueries

External programs can use this technique to scrape metrics, though it is preferred to use a Prometheus export.

Using Prometheus export
^^^^^^^^^^^^^^^^^^^^^^^
The internal web server exposes Prometheus formatted metrics at

.. http:get:: /metrics

The Prometheus name are the names listed in `metricnames`_, prefixed with ``pdns_recursor_`` and with hyphens substituted by underscores.
For example::

  # HELP pdns_recursor_all_outqueries Number of outgoing UDP queries since starting
  # TYPE pdns_recursor_all_outqueries counter
  pdns_recursor_all_outqueries 7


Sending metrics over SNMP
-------------------------

The recursor can export statistics over SNMP and send traps from :doc:`Lua <lua-scripting/index>`, provided support is compiled into the Recursor and :ref:`setting-yaml-snmp.agent` set.

For the details of all values that can be retrieved using SNMP, see the `SNMP MIB <https://github.com/PowerDNS/pdns/blob/master/pdns/recursordist/RECURSOR-MIB.txt>`_.


.. _metricnames:

Gathered Information
--------------------

These statistics are gathered.

It should be noted that answers0-1 + answers1-10 + answers10-100 + answers100-1000 + answers-slow + packetcache-hits + over-capacity-drops + policy-drops = questions.

Also note that unauthorized-tcp and unauthorized-udp packets do not end up in the 'questions' count.

.. include:: rec-metrics-gen.rst

