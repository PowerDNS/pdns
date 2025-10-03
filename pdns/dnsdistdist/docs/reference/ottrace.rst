OpenTelemetry Tracing
---------------------

.. warning::
   Tracing support is considered experimental. The output, configuration, and any other details
   may change at any time.

Since version 2.1.0, when :program:`dnsdist` is built with ProtoBuf support, sent messages (using e.g. :func:`RemoteLogResponseAction`) can contain `OpenTelemetry traces <https://opentelemetry.io/docs/concepts/signals/traces>`__ data.

To enable tracing, use :func:`setOpenTelemetryTracing(true) <setOpenTelemetryTracing>` in your configuration, or ``logging.open_telemetry_tracing`` to ``true`` in your YAML configuration.
It is also possible to call :func:`setOpenTelemetryTracing` at runtime.
Once enabled, Rules can be used to turn on tracing on a per-query basis.

Per-query tracing can be enabled using the :func:`SetTraceAction` or :func:`SetTraceResponseAction`. However :program:`dnsdist` captures some data before rules processing in order to have tracing information from before the rules are evaluated.
When tracing is enabled in the query, :program:`dnsdist` stores start and end times of certain (but not all) functions that are called during the lifetime of the query and the response.
It is recommended to send the traces out through a RemoteLogger in ResponseRules, to capture as much information as possible.

.. note::
   At the moment, the ProtoBuf message is sent out **during** the processing of the response rules.
   Hence, the traces are not complete.
   There are plans to remedy this, but no timeline to do so.

Tracing uses more memory and CPU than usual query processing and it is recommended to enable tracing only for certain queries using specific :doc:`selectors <selectors>`.

Example configuration
=====================

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
     - name: Do PB logging
       selector:
         type: All
       action:
         type: RemoteLog
         logger_name: pblog

Passing Trace ID and Span ID to downstream servers
==================================================

When storing traces, it is beneficial to correlate traces of the same query through different applications.
The `PowerDNS Recursor <https://doc.powerdns.com/recursor>`__ (since 5.3.0) supports the experimental `draft-edns-otel-trace-ids <https://github.com/PowerDNS/draft-edns-otel-trace-ids>`__ EDNS option to pass the trace identifier.
The :doc:`DNSQuestion object <dq>` supports the :func:`getTraceID <DNSQuestion:getTraceID>` method to retrieve the trace identifier as a binary string.
Combining all this, a :func:`LuaAction` can be used to add this EDNS option to the query.

.. code-block:: yaml

   - name: Add TraceID to EDNS for backend
     selector:
       type: All
     action:
       type: Lua
       function_code: |
         return function (dq)
           tid = dq:getTraceID()
           if (tid ~= nil) then
             -- PowerDNS Recursor uses EDNS Option Code 65500.
             dq:setEDNSOption(65500, "\000\000" .. tid)
           end
           return DNSAction.None
         end

Optionally, the Span ID can also be added to the query.
This value is retrieved with the :func:`getSpanID <DNSQuestion:getSpanID>` function and can be added to the query as follows:

.. code-block:: yaml

   - name: Add TraceID and SpanID to EDNS for backend
     selector:
       type: All
     action:
       type: Lua
       function_code: |
         return function (dq)
           tid = dq:getTraceID()
           sid = dq:getSpanID()
           if (tid ~= nil and sid ~= nil) then
             -- PowerDNS Recursor uses EDNS Option Code 65500.
             dq:setEDNSOption(65500, "\000\000" .. tid .. sid)
           end
           return DNSAction.None
         end
