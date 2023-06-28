Custom Metrics
=====================================

You can define your own metrics that can be updated using Lua.

The first step is to declare a new metric using :func:`declareMetric`. In 1.8.0 the declaration had to be done at configuration time, but since 1.8.1 it can be done at any point.

Then you can update those at runtime using the following functions, depending on the metric type:

 * manipulate counters using :func:`incMetric` and  :func:`decMetric`
 * update a gauge using :func:`setMetric`

.. function:: declareMetric(name, type, description [, prometheusName]) -> bool

  .. versionadded:: 1.8.0

  .. versionchanged:: 1.8.1
    This function can now be used at runtime, instead of only at configuration time.

  Return true if declaration was successful

  :param str name: The name of the metric, lowercase alphanumerical characters and dashes (-) only
  :param str type: The desired type in ``gauge`` or ``counter``
  :param str name: The description of the metric
  :param str prometheusName: The name to use in the prometheus metrics, if supplied. Otherwise the regular name will be used, prefixed with ``dnsdist_`` and ``-`` replaced by ``_``.

.. function:: incMetric(name [, step]) -> int

  .. versionadded:: 1.8.0

  .. versionchanged:: 1.8.1
    Optional ``step`` parameter added.

  Increment counter by one (or more, see the ``step`` parameter), will issue an error if the metric is not declared or not a ``counter``
  Return the new value

  :param str name: The name of the metric
  :param int step: By how much the counter should be incremented, default to 1.

.. function:: decMetric(name) -> int

  .. versionadded:: 1.8.0

  .. versionchanged:: 1.8.1
    Optional ``step`` parameter added.

  Decrement counter by one (or more, see the ``step`` parameter), will issue an error if the metric is not declared or not a ``counter``
  Return the new value

  :param str name: The name of the metric
  :param int step: By how much the counter should be decremented, default to 1.

.. function:: getMetric(name) -> double

  .. versionadded:: 1.8.0

  Get metric value

  :param str name: The name of the metric

.. function:: setMetric(name, value) -> double

  .. versionadded:: 1.8.0

  Set the new value, will issue an error if the metric is not declared or not a ``gauge``
  Return the new value

  :param str name: The name of the metric
  :param double value: The new value
