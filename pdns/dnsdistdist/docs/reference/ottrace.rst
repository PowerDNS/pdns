OpenTelemetry Tracing
---------------------

.. warning::
   Tracing support is considered experimental. The output, configuration, and any other details
   may change at any time.

Since version 2.1.0, when :program:`dnsdist` is built with ProtoBuf support, sent messages (using e.g. :func:`RemoteLogResponseAction`) can contain `OpenTelemetry traces <https://opentelemetry.io/docs/concepts/signals/traces>`__ data.

To enable tracing, use :func:`setOpenTelemetryTracing(true) <setOpenTelemetryTracing>` in your configuration, or ``logging.open_telemetry_tracing.enabled`` to ``true`` in your :ref:`YAML Logging Configuration <yaml-settings-LoggingConfiguration>`.
It is also possible to call :func:`setOpenTelemetryTracing` at runtime.
Once enabled, Rules can be used to turn on tracing on a per-query basis.

Per-query tracing can be enabled using the :func:`SetTraceAction`. However, :program:`dnsdist` captures some data before rules processing in order to have tracing information from before the rules are evaluated.
When tracing is enabled in the query, :program:`dnsdist` stores start and end times of certain (but not all) functions that are called during the lifetime of the query and the response.
It is recommended to send the traces out through a RemoteLogger in ResponseRules, to capture as much information as possible.

Tracing uses more memory and CPU than usual query processing and it is recommended to enable tracing only for certain queries using specific :doc:`selectors <selectors>`.

Example configurations
======================

In this configuration, the :class:`RemoteLogger` is passed directly to the :func:`SetTrace <SetTraceAction>` action.
Doing this ensures that no matter what happens with the query (timeout, self-answered, cache-hit, dropped, answered by the backend), the trace will be sent out.
When sending the trace in this way, the Protobuf message is essentially empty apart from the OpenTelemetry Trace.

.. md-tab-set::

  .. md-tab-item:: YAML

    .. code-block:: yaml

      logging:
        open_telemetry_tracing:
          enabled: true
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

  .. md-tab-item:: Lua

    .. code-block:: lua

      -- newServer should go here
      rl = newRemoteLogger('127.0.0.1:5301')
      setOpenTelemetryTracing(true)

      addAction(AllRule(), SetTraceAction(true, {remoteLoggers={rl}}), {name="Enable tracing"})

Should you only want to receive the trace after a response was received from the backend, including a fully filled Protobuf message, a :func:`RemoteLog <RemoteLogAction>` action can be used:

.. md-tab-set::

  .. md-tab-item:: YAML

      .. code-block:: yaml

         logging:
           open_telemetry_tracing:
             enabled: true
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

  .. md-tab-item:: Lua

    To receive *all* trace spans, set the ``delay`` option of the :func:`addResponseAction`. This will delay the sending of the ProtoBuf message to after the response has been sent to the client.

    .. code-block:: lua

      rl = newRemoteLogger('127.0.0.1:5301')
      setOpenTelemetryTracing(true)

      addAction(AllRule(), SetTraceAction(true), {name="Enable tracing"})
      addResponseAction(AllRule(), RemoteLogResponseAction(rl, nil, false, {}, {}, true), {name="Do PB logging"})

Passing Trace ID and Span ID to downstream servers
--------------------------------------------------

When storing traces, it is beneficial to correlate traces of the same query through different applications.
The `PowerDNS Recursor <https://doc.powerdns.com/recursor>`__ (since 5.3.0) supports the experimental `TRACEPARENT <https://github.com/PowerDNS/draft-edns-otel-trace-ids>`__ EDNS option to pass the trace identifier.

This can be easily achieved by adding the `send_downstream_traceparent` option with the desired EDNS OptionCode.

.. md-tab-set::

  .. md-tab-item:: YAML

    .. code-block:: yaml

      query_rules:
        - name: Add TraceID to EDNS for backend
          selector:
            type: All
          action:
            type: SetTrace
            value: true
            send_downstream_traceparent: true

    .. code-block:: lua

      addAction(AllRule(), SetTraceAction(true, {sendDownstreamTraceparent=true}), {name="Enable tracing"})

Accepting TRACEPARENT from upstream servers
-------------------------------------------

:program:`dnsdist` can also use a Trace ID and optional Span ID from an incoming query.
It will not do this by default, but this can be configured to do so.
When set, the Trace and Span IDs from the query will be used.
Should there be no ID in the incoming query, a random ID will be generated.

.. md-tab-set::

  .. md-tab-item:: YAML

    Set the ``use_incoming_traceid`` argument to ``true`` in the SetTrace action.

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

  .. md-tab-item:: Lua

    .. code-block:: lua

      addAction(AllRule(), SetTraceAction(true, {useIncomingTraceparent=true}), {name="Enable tracing"})

As :program:`dnsdist` keeps EDNS existing options in the query, the TRACEPARENT option is passed as-is to the backend, which might not be desirable.
Using the ``strip_incoming_traceparent`` boolean option, the EDNS option will be removed from the query.

By default, :program:`dnsdist` uses 65500 for the TRACEPARENT option code. This code can be changed using the ``traceparent_edns_option_code`` option in the YAML config and the ``traceparentOptionCode`` for Lua.

Note that this will only happen when ``value`` is set to ``true``.

Accepting and sending TRACEPARENT
---------------------------------

The following example makes :program:`dnsdist` accept a TRACEPARENT, and update it with its own Span ID before sending it downstream:

.. md-tab-set::

  .. md-tab-item:: YAML

    .. code-block:: yaml

      query_rules:
        - name: Enable tracing
          selector:
            # Just as an example, in production don't trace all the queries
            type: All
          action:
            type: SetTrace
            value: true
            send_downstream_traceparent: true
            use_incoming_traceparent: true

  .. md-tab-item:: Lua

    .. code-block:: lua

      addAction(AllRule(), SetTraceAction(true, {useIncomingTraceparent=true, sendDownstreamTraceparent=true}), {name="Enable tracing"})

Creating Trace Spans from Lua
=============================

.. versionadded:: 2.2.0

It is possible to create Spans inside :func:`LuaRules <LuaRule>` or :func:`LuaResponseRules <LuaResponseRule>` in order to track performance of your Lua code.
To do this, you can call the :func:`withTraceSpan` function.
This function takes a string that is the name of the Span and the function with will be instrumented.

Trace Spans from LuaActions
---------------------------

.. code-block:: lua

  function myLuaAction(dq)
    setSpanAttribute("attr-in-the-rule-span", "hello from Lua!")
    withTraceSpan(
      'my-trace-span',
      function ()
        setSpanAttribute("some.key", "some-value")
        -- Do some actual things with the DNSQuestion here
      end
    )
    return DNSAction.None
  end

Within the function body, you can create more spans by calling :func:`withTraceSpan` again.

.. code-block:: lua

  function myLuaAction(dq)
    withTraceSpan(
      'my-trace-span',
      function ()
        -- Some set up
        setSpanAttribute("some.key", "some-value")

        -- This will create a child span of 'my-trace-span'
        withTraceSpan(
          'inner-span',
          function ()
            -- Do some longer-running thing
          end
        )
      end
    )
    return DNSAction.None
  end

Using :func:`withTraceSpan` or :func:`setSpanAttribute` when tracing is not enabled is completely safe and transparent.
The Lua code will be run, but no Trace Span will be created.

Trace Spans from maintenance functions
--------------------------------------

It is possible to create Spans inside :func:`Maintenance <maintenance>` or :func:`Maintenance callback <addMaintenanceCallback>` functions in order to track performance of your Lua code.
To do this, you can call the :func:`withTraceSpan` function inside your function.
This function takes a string that is the name of the Span and the function with will be instrumented.

.. code-block:: lua

  function maintenance()
    setSpanAttribute("attr-in-the-span", "hello from Lua!")
    withTraceSpan(
      'my-maintenance-trace-span',
      function ()
        setSpanAttribute("some.key", "some-value")
      end
    )
  end

Within the function body, you can create more spans by calling :func:`withTraceSpan` again.

.. code-block:: lua

  function maintenance()
    setSpanAttribute("attr-in-the-span", "hello from Lua!")
    withTraceSpan(
      'my-maintenance-trace-span',
      function ()
        setSpanAttribute("some.key", "some-value")

        -- This will create a child span of 'my-maintenance-trace-span'
        withTraceSpan(
          'inner-span',
          function ()
            -- Do something here
          end
        )
      end
    )
  end

Using :func:`withTraceSpan` when tracing is disabled is completely safe and transparent.
The Lua code will be run, but no Trace Span will be created.

Functions
---------

The following functions are always available, but only produce Trace Spans within the following contexts:

* :func:`LuaAction`
* :func:`maintenance`
* Any function added with :func:`addMaintenanceCallback`

.. function:: withTraceSpan(name, func)

  .. versionadded:: 2.2.0

  Open an OpenTelemetry Trace Span called ``name`` that instruments function ``func``.
  This method can be called safely when Tracing is not enabled for the query or when :program:`dnsdist` is built without Protobuf support.

  :param string name: The name for this Span
  :param func function: The function to run. This function takes no parameters

.. function:: setSpanAttribute(key, value)

  .. versionadded:: 2.2.0

  Add an OpenTelemetry Trace Span attribute to the current span.
  In the context of a :func:`LuaAction` or :func:`maintenance`, this sets an attribute on the function's Span.
  When used inside the function passed to :func:`withTraceSpan`, it will set the Attribute on the enclosed span.

  This method can be called safely when Tracing is not enabled for the query or when :program:`dnsdist` is built without Protobuf support.

  :param string key: The key for attribute
  :param string value: The value of the attribute
