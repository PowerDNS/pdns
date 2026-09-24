OTLP Logging Reference
======================

Since version 2.2.0, :program:`dnsdist` can send :doc:`OpenTelemetry traces <ottrace>` with `OTLP <https://opentelemetry.io/docs/specs/otlp/>`__ over HTTP.

Using OTLP directly allows for easy integration of dnsdist in existing observability infrastructure.

.. function:: newOtlpLogger(address[, options])

  .. versionadded:: 2.2.0

  Create an OTLP logger object, to use with :func:`SetTraceAction`, :func:`RemoteLogAction`, :func:`RemoteLogResponseAction`, and :func:`setOpenTelemetryInternalTrace`.

  :param string address: The URL of the endpoint. Must contain the scheme (http, https) and the path (like /v1/traces)
  :param table options: A table with key: value pairs with options

  The following options can be set:

  * ``batchSize``: Maximum number of traces to send to the endpoint in a single batch, default 100.
  * ``httpFastOpen``: Whether or not to use TCP fast-open, default is false.
  * ``httpTimeout``: Timeout in seconds for the connection to establish, default is 2.
  * ``httpsVerify``: Verify SSL/TLS certificate when connecting, default is true.
  * ``interval``: Interval in seconds to wait before sending the next batch of OTLP messages, 5 by default.
  * ``queueSize``: Maximum number of traces in the backlog, default is 500.
