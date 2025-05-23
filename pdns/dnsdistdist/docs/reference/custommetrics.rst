Custom Metrics
=====================================

You can define your own metrics that can be updated using Lua.

The first step is to declare a new metric using :func:`declareMetric`. In 1.8.0 the declaration had to be done at configuration time, but since 1.8.1 it can be done at any point.

Then you can update those at runtime using the following functions, depending on the metric type:

 * manipulate counters using :func:`incMetric` and  :func:`decMetric`
 * update a gauge using :func:`setMetric`

.. function:: declareMetric(name, type, description [, prometheusName|options]) -> bool

  .. versionadded:: 1.8.0

  .. versionchanged:: 1.8.1
    This function can now be used at runtime, instead of only at configuration time.

  .. versionchanged:: 2.0.0
    This function now takes options, with ``withLabels`` option added. ``prometheusName`` can now be provided in options.

 .. note::
    Labels are only available for prometheus. Metrics with labels are otherwise ignored.

  Re-declaring an existing metric with the same name and type will not reset it.
  Re-declaring with the same name but a different type will cause one of them to be masked.

  Returns true if declaration was successful.

  :param str name: The name of the metric, lowercase alphanumerical characters and dashes (-) only
  :param str type: The desired type in ``gauge`` or ``counter``
  :param str description: The description of the metric
  :param str prometheusName: The name to use in the prometheus metrics, if supplied. Otherwise, the regular name will be used, prefixed with ``dnsdist_`` and ``-`` replaced by ``_``
  :param table options: A table with key: value pairs with metric options.

  Options:

  * ``name``: str - The name to use in the prometheus metrics, if supplied. Otherwise, the regular name will be used, prefixed with ``dnsdist_`` and ``-`` replaced by ``_``
  * ``withLabels=false``: bool - If set to true, labels will be expected when updating this metric and it will not be automatically created without labels. Defaults to ``false``, which automatically creates this metric without labels with default value.

.. function:: incMetric(name [, step|options]) -> int

  .. versionadded:: 1.8.0

  .. versionchanged:: 1.8.1
    Optional ``step`` parameter added.

  .. versionchanged:: 2.0.0
    This function now takes options, with ``labels`` option added. ``step`` can now be provided in options.

 .. note::
    Labels are only available for prometheus. Metrics with labels are otherwise ignored.

  Increment counter by one (or more, see the ``step`` parameter), will issue an error if the metric is not declared or not a ``counter``.

  Returns the new value.

  :param str name: The name of the metric
  :param int step: By how much the counter should be incremented, default to 1
  :param table options: A table with key: value pairs with metric options.

  Options:

  * ``step``: int - By how much the counter should be incremented, default to 1
  * ``labels={}``: table - Set of key: value pairs with labels and their values that should be used to increment the metric. Different combinations of labels have different metric values.

.. function:: decMetric(name [, step|options]) -> int

  .. versionadded:: 1.8.0

  .. versionchanged:: 1.8.1
    Optional ``step`` parameter added.

  .. versionchanged:: 2.0.0
    This function now takes options, with ``labels`` option added. ``step`` can now be provided in options.

 .. note::
    Labels are only available for prometheus. Metrics with labels are otherwise ignored.

  Decrement counter by one (or more, see the ``step`` parameter), will issue an error if the metric is not declared or not a ``counter``.

  Returns the new value.

  :param str name: The name of the metric
  :param int step: By how much the counter should be decremented, default to 1.
  :param table options: A table with key: value pairs with metric options.

  Options:

  * ``step``: int - By how much the counter should be decremented, default to 1
  * ``labels={}``: table - Set of key: value pairs with labels and their values that should be used to decrement the metric. Different combinations of labels have different metric values.

.. function:: getMetric(name [, options]) -> double

  .. versionadded:: 1.8.0

  .. versionchanged:: 2.0.0
    This function now takes options, with ``labels`` option added.

 .. note::
    Labels are only available for prometheus. Metrics with labels are otherwise ignored.

  Get metric value.

  :param str name: The name of the metric
  :param table options: A table with key: value pairs with metric options.

  Options:

  * ``labels={}``: table - Set of key: value pairs with labels and their values that should be used to read the metric. Different combinations of labels have different metric values.

.. function:: setMetric(name, value [, options]) -> double

  .. versionadded:: 1.8.0

  .. versionchanged:: 2.0.0
    This function now takes options, with ``labels`` option added.

 .. note::
    Labels are only available for prometheus. Metrics with labels are otherwise ignored.

  Set the new value, will issue an error if the metric is not declared or not a ``gauge``.

  Return the new value.

  :param str name: The name of the metric
  :param double value: The new value
  :param table options: A table with key: value pairs with metric options.

  Options:

  * ``labels={}``: table - Set of key: value pairs with labels and their values that should be used to set the metric. Different combinations of labels have different metric values.
