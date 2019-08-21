Lua Scripting and Statistics
============================

The Lua engine can generate and retrieve metrics. 

Generating Metrics
------------------
Custom metrics can be added which will be shown in the output of 'rec_control get-all' and sent to the metrics server over the Carbon protocol.
They will also appear in the JSON HTTP API.

Create a custom metric with:

.. code-block:: lua

  myMetric=getMetric("myspecialmetric")

.. function:: getMetric(name) -> Metric

  Returns the :class:`Metric` object with the name ``name``, creating the metric if it does not exist.

  :param str name: The metric to retrieve

.. class:: Metric

  Represents a custom metric

  .. method:: Metric::inc()

    Increase metric by 1

  .. method:: Metric::incBy(amount)

    Increase metric by amount

    :param int amount:

  .. method:: Metric::set(to)

    Set metric to value ``to``

    :param int to:

  .. method:: Metric::get() -> int

    Get value of metric

Metrics are shared across all of PowerDNS and are fully atomic and high performance.
A :class:`Metric` object is effectively a pointer to an atomic value.

Note that metrics live in the same namespace as 'system' metrics. So if you generate one that overlaps with a PowerDNS stock metric, you will get double output and weird results.

Looking at Statistics
---------------------
.. versionadded:: 4.1.0

Statistics can be retrieved from Lua using the :func:`getStat` call.

.. function:: getStat(name) -> int

  Returns the value of a statistic.

  :param string name: The name of the statistic.

For example, to retrieve the number of cache misses:

.. code-block:: Lua

    cacheMisses = getStat("cache-misses")

Please be aware that retrieving statistics is a relatively costly operation, and as such should for example not be done for every query.
