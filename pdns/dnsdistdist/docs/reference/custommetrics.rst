Custom Metrics
=====================================

You can define at configuration time your own metrics that can be updated using Lua.

The first step is to declare a new metric using :func:`declareMetric`.

Then you can update those at runtime using the following functions, depending on the metric type:

 * manipulate counters using :func:`incMetric` and  :func:`decMetric`
 * update a gauge using :func:`setMetric`

.. function:: declareMetric(name, type, description [, prometheusName]) -> bool

  .. versionadded:: 1.8.0

  Return true if declaration was successful

  :param str name: The name of the metric, lowercase alphanumerical characters and dashes (-) only
  :param str type: The desired type in ``gauge`` or ``counter``
  :param str name: The description of the metric
  :param str prometheusName: The name to use in the prometheus metrics, if supplied. Otherwise the regular name will be used, prefixed with ``dnsdist_`` and ``-`` replaced by ``_``.

.. function:: incMetric(name) -> int

  .. versionadded:: 1.8.0

  Increment counter by one, will issue an error if the metric is not declared or not a ``counter``
  Return the new value

  :param str name: The name of the metric

.. function:: decMetric(name) -> int

  .. versionadded:: 1.8.0

  Decrement counter by one, will issue an error if the metric is not declared or not a ``counter``
  Return the new value

  :param str name: The name of the metric

.. function:: getMetric(name) -> double

  .. versionadded:: 1.8.0

  Get metric value

  :param str name: The name of the metric

.. function:: setMetric(name, value) -> double

  .. versionadded:: 1.8.0

  Set the new value, will issue an error if the metric is not declared or not a ``gauge``
  Return the new value

  :param str name: The name of the metric
