OpenTelemetryTraceCondition
---------------------------

An ``OpenTelemetryTraceCondition`` object represents a condition to trigger generating :ref:`opentelemetry_tracing`.
These conditions con be configured in a settings file (see :ref:`setting-yaml-logging.opentelemetry_trace_conditions`) or manipulated at runtime using the REST API calls listed in :doc:`endpoint-ottraceconditions`.

.. json:schema:: OpenTelemetryTraceCondition

**Example**:

.. code-block:: json

   {
     "acl": "192.0.2.1/32",
     "edns_option_required": false,
     "qid": 1,
     "qnames": ["example.com.", "example.net."],
     "qtypes": ["AAAA", "A"],
     "traceid_only": false
     "type": "OpenTelemetryTraceCondition"
   }

