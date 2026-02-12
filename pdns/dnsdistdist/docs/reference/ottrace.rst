OpenTelemetry Tracing
---------------------

.. warning::
   Tracing support is considered experimental. The output, configuration, and any other details
   may change at any time.

Since version 2.1.0, when :program:`dnsdist` is built with ProtoBuf support, sent messages (using e.g. :func:`RemoteLogResponseAction`) can contain `OpenTelemetry traces <https://opentelemetry.io/docs/concepts/signals/traces>`__ data.

To enable tracing, use :func:`setOpenTelemetryTracing(true) <setOpenTelemetryTracing>` in your configuration, or ``logging.open_telemetry_tracing`` to ``true`` in your:ref:`YAML Logging Configuration <yaml-settings-LoggingConfiguration>`.
It is also possible to call :func:`setOpenTelemetryTracing` at runtime.
Once enabled, Rules can be used to turn on tracing on a per-query basis.

Per-query tracing can be enabled using the :func:`SetTraceAction`. However, :program:`dnsdist` captures some data before rules processing in order to have tracing information from before the rules are evaluated.
When tracing is enabled in the query, :program:`dnsdist` stores start and end times of certain (but not all) functions that are called during the lifetime of the query and the response.
It is recommended to send the traces out through a RemoteLogger in ResponseRules, to capture as much information as possible.

Tracing uses more memory and CPU than usual query processing and it is recommended to enable tracing only for certain queries using specific :doc:`selectors <selectors>`.

Example configuration
=====================

In this configuration, the RemoteLogger is passed directly to the ``SetTrace`` action.
Doing this ensures that no matter what happens with the query (timeout, self-answered, cache-hit, dropped, answered by the backend), the trace will be sent out.
When sending the trace in this way, the Protobuf message is essentially empty apart from the OpenTelemetry Trace.

.. code-block:: yaml

   logging:
     open_telemetry_tracing: true
   remote_logging:
     protobuf_loggers:
       - name: pblog
         address: 127.0.0.1:5301
   query_rules:
     - name: Enable tracing
       selector:
         # Just as an example, in production don't trace all the queries
         type: All
       action:
         type: SetTrace
         value: true
         remote_loggers:
           - pblog

Should you only want to receive the trace, including a fully filled Protobuf message, a `RemoteLog` can be used:

.. code-block:: yaml

   logging:
     open_telemetry_tracing: true
   remote_logging:
     protobuf_loggers:
       - name: pblog
         address: 127.0.0.1:5301
   query_rules:
     - name: Enable tracing
       selector:
         # Just as an example, in production don't trace all the queries
         type: All
       action:
         type: SetTrace
         value: true
    response_rules:
      - name: Send PB log
        selector:
          type: All
        action:
          type: RemoteLog
          logger_name: pblog
          # Delay ensures that the PB message is sent
          # after the response is sent to client, instead
          # of immediately. This ensures all Trace Spans
          # have proper end timestamps.
          delay: true

Passing Trace ID and Span ID to downstream servers
==================================================

When storing traces, it is beneficial to correlate traces of the same query through different applications.
The `PowerDNS Recursor <https://doc.powerdns.com/recursor>`__ (since 5.3.0) supports the experimental `TRACEPARENT <https://github.com/PowerDNS/draft-edns-otel-trace-ids>`__ EDNS option to pass the trace identifier.

This can be easily achieved by adding the `downstream_edns_traceparent_option_code` option with the desired EDNS OptionCode.

.. code-block:: yaml

  query_rules:
    - name: Add TraceID to EDNS for backend
      selector:
        type: All
      action:
        type: SetTrace
        value: true
        downstream_edns_traceparent_option_code: 65500

Accepting TRACEPARENT from upstream servers
===========================================

:program:`dnsdist` can also use a Trace ID and optional Span ID from an incoming query.
It will not do this by default, but this can be configured with the ``use_incoming_traceid`` argument.
When set to ``true`` incoming Trace and Span IDs will be used.
Should there be no ID in the incoming query, a random ID will be generated.

.. code-block:: yaml

   query_rules:
     - name: Enable tracing
       selector:
         # Just as an example, in production don't trace all the queries
         type: All
       action:
         type: SetTrace
         value: true
         use_incoming_traceparent: true

As :program:`dnsdist` keeps EDNS existing options in the query, the TRACEPARENT option is passed as-is to the backend, which might not be desirable.
Using the ``strip_incoming_traceparent`` boolean option, the EDNS option will be removed from the query.

By default, :program:`dnsdist` uses 65500 for the TRACEPARENT option code. This code can be changed using the ``traceparent_edns_option_code`` option.

Note that this will only happen when ``value`` is set to ``true``.

Accepting and sending TRACEPARENT
=================================

The following example makes :program:`dnsdist` accept a TRACEPARENT, and update it with its own Span ID before sending it downstream:

.. code-block:: yaml

  query_rules:
    - name: Enable tracing
      selector:
        # Just as an example, in production don't trace all the queries
        type: All
      action:
        type: SetTrace
        value: true
        downstream_edns_traceparent_option_code: 65500
        use_incoming_traceparent: true
