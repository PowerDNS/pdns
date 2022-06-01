Custom Metrics
=====================================

You can define at configuration time your own metrics that can be updated using lua.

The first step is to declare a new metric using :func:`declareMetric`.

Then you can update those at runtime using the following functions, depending on the metric type:

 * manipulate counters using :func:`incMetric` and  :func:`decMetric`
 * update a gauge using :func:`setMetric`

.. function:: declareMetric(name, type) -> bool

  .. versionadded:: 1.x

  Return true if declaration was successful

  :param str name: The name of the metric, lowercase alnum characters only
  :param str type: The desired type in ``gauge`` or ``counter``

.. function:: incMetric(name) -> int

  .. versionadded:: 1.x

  Increment counter by one, will issue an error if the metric is not declared or not a ``counter``
  Return the new value

  :param str name: The name of the metric

.. function:: decMetric(name) -> int

  .. versionadded:: 1.x

  Decrement counter by one, will issue an error if the metric is not declared or not a ``counter``
  Return the new value

  :param str name: The name of the metric

.. function:: getMetric(name) -> double

  .. versionadded:: 1.x

  Get metric value

  :param str name: The name of the metric

.. function:: setMetric(name, value) -> double

  .. versionadded:: 1.x

  Decrement counter by one, will issue an error if the metric is not declared or not a ``counter``
  Return the new value

  :param str name: The name of the metric


                   
