OpenTelemetryTraceConditions endpoint
=====================================

.. Note::
   All modifications using this endpoint are not persistent.
   Reloading the configuration using ``rec_control reload-yaml`` will revert the trace conditions back to the conditions read from the configuration file(s).

.. http:get:: /api/v1/servers/:server_id/ottraceconditions

  Get all :json:object:`OpenTelemetryTraceCondition` from the server. Note that while the settings file allows a list of subnets to be associated with a condition, this list is flattened: one subnet per condition.

  :query server_id: The name of the server

.. http:post:: /api/v1/servers/:server_id/ottraceconditions

  Creates a new trace condition. The client body must contain a :json:object:`OpenTelemetryTraceCondition`.

  :query server_id: The name of the server

.. http:get:: /api/v1/servers/:server_id/ottraceconditions/:subnet

  Returns trace condition information.

  :query server_id: The name of the server
  :query subnet: The subnet of the :json:object:`OpenTelemetryTraceCondition`. URL encode subnet, for example ``192.0.2.1/32`` becomes ``192.0.2.1%2F32``.

.. http:delete:: /api/v1/servers/:server_id/ottraceconditions/:subnet

  Deletes this zone, all attached metadata and rrsets.

  :query server_id: The name of the server
  :query subnet: The subnet of the :json:object:`OpenTelemetryTraceCondition`. URL encode subnet, for example ``192.0.2.1/32`` becomes ``192.0.2.1%2F32``.
