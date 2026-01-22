OpenTelemetryTraceCondition
---------------------------

An ``OpenTelemetryTraceCondition`` object represents a condition to trigger generating :ref:`opentelemetry_tracing`.
These conditions con be configured in a settings file (see :ref:`setting-yaml-logging.opentelemetry_trace_conditions`) or manipulated at runtime using the REST API calls listed in :doc:`endpoint-ottraceconditions`.

.. json:object:: OpenTelemetryTraceCondition

  Represents an OpenTelemetryTrace condition.

  :property string acl: The subnet of the entry. Note that the YAML settings file allows multiple subnets for convenience. This object does not allow multiple subnets to be specified.
  :property string type: set to "OpenTelemetryTraceCondition"
  :property bool edns_option_required: See :ref:`opentelemetry_tracing`
  :property number qid: A specific query id
  :property [DNSName] qnames: List of names
  :property [QType] qtypes: List of qtypes, represented as string
  :property bool traceid_only: See :ref:`opentelemetry_tracing`

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

