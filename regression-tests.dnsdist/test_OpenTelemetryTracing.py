#!/usr/bin/env python

import base64
import binascii
import dns.message
import dns.rrset
import dns.rdataclass
import dns.rdatatype
import dns.edns
import time

import opentelemetry.proto.trace.v1.trace_pb2
import google.protobuf.json_format

import test_Protobuf


class DNSDistOpenTelemetryProtobufTest(test_Protobuf.DNSDistProtobufTest):
    def checkProtobufOpenTelemetryBase(self, msg):
        self.assertTrue(msg)
        self.assertTrue(msg.HasField("openTelemetry"))

    def sendQueryAndGetProtobuf(
        self, useTCP=False, traceID="", spanID="", ednsTraceIDOpt=65500
    ):
        name = "query.ot.tests.powerdns.com."

        target = "target.ot.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")

        if traceID != "":
            ottrace = dns.edns.GenericOption(str(ednsTraceIDOpt), "\x00\x00")
            ottrace.data += binascii.a2b_hex(traceID)
            if spanID != "":
                ottrace.data += binascii.a2b_hex(spanID)
            query = dns.message.make_query(
                name, "A", "IN", use_edns=True, options=[ottrace]
            )

        response = dns.message.make_response(query)

        rrset = dns.rrset.from_text(
            name, 3600, dns.rdataclass.IN, dns.rdatatype.CNAME, target
        )
        response.answer.append(rrset)

        rrset = dns.rrset.from_text(
            target, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1"
        )
        response.answer.append(rrset)

        if useTCP:
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        else:
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        if self._protobufQueue.empty():
            # let the protobuf messages the time to get there
            time.sleep(1)

        # check the protobuf message corresponding to the UDP query
        return self.getFirstProtobufMessage()


class DNSDistOpenTelemetryProtobufBaseTest(DNSDistOpenTelemetryProtobufTest):
    def doTest(self, wasDelayed=False, useTCP=False, traceID="", spanID=""):
        msg = self.sendQueryAndGetProtobuf(useTCP, traceID, spanID)

        self.assertTrue(msg.HasField("openTelemetryTraceID"))
        self.assertTrue(msg.openTelemetryTraceID != "")

        if traceID != "":
            self.assertEqual(msg.openTelemetryTraceID, binascii.a2b_hex(traceID))

        self.assertTrue(msg.HasField("openTelemetryData"))
        traces_data = opentelemetry.proto.trace.v1.trace_pb2.TracesData()
        traces_data.ParseFromString(msg.openTelemetryData)
        ot_data = google.protobuf.json_format.MessageToDict(
            traces_data, preserving_proto_field_name=True
        )

        self.assertEqual(len(ot_data["resource_spans"]), 1)
        self.assertEqual(len(ot_data["resource_spans"][0]["resource"]["attributes"]), 1)

        # Ensure all attributes exist
        for field in ot_data["resource_spans"][0]["resource"]["attributes"]:
            self.assertTrue(field["key"] in ["service.name"])

        # Ensure the values are correct
        # TODO: query.remote with port
        msg_scope_attr_keys = [
            v["key"]
            for v in ot_data["resource_spans"][0]["scope_spans"][0]["scope"][
                "attributes"
            ]
        ]
        self.assertListEqual(msg_scope_attr_keys, ["hostname"])

        root_span_attr_keys = [
            v["key"]
            for v in ot_data["resource_spans"][0]["scope_spans"][0]["spans"][0][
                "attributes"
            ]
        ]
        self.assertListEqual(
            root_span_attr_keys,
            ["query.qname", "query.qtype", "query.remote.address", "query.remote.port"],
        )

        # No way to guess the test port, but check the rest of the values
        root_span_attrs = {
            v["key"]: v["value"]["string_value"]
            for v in ot_data["resource_spans"][0]["scope_spans"][0]["spans"][0][
                "attributes"
            ]
            if v["key"] not in ["query.remote.port"]
        }
        self.assertDictEqual(
            {
                "query.qname": "query.ot.tests.powerdns.com",
                "query.qtype": "A",
                "query.remote.address": "127.0.0.1",
            },
            root_span_attrs,
        )

        msg_span_name = {
            v["name"] for v in ot_data["resource_spans"][0]["scope_spans"][0]["spans"]
        }

        funcs = {
            "processQuery",
            "applyRulesToQuery",
            "Rule: Enable tracing",
            "selectBackendForOutgoingQuery",
            "processResponse",
            "applyRulesToResponse",
            "Rule: Do PB logging",
        }

        if useTCP:
            funcs.add("IncomingTCPConnectionState::handleQuery")
        else:
            funcs.add("processUDPQuery")
            funcs.add("assignOutgoingUDPQueryToBackend")

        if wasDelayed:
            funcs.add("processResponseAfterRules")

        self.assertSetEqual(msg_span_name, funcs)

        traceId = base64.b64encode(msg.openTelemetryTraceID).decode()
        for msg_span in ot_data["resource_spans"][0]["scope_spans"][0]["spans"]:
            self.assertEqual(
                msg_span["trace_id"],
                traceId,
                f"span {msg_span} does not have the trace id {traceId} of the protobuf message",
            )

        if spanID != "":
            for span in ot_data["resource_spans"][0]["scope_spans"][0]["spans"]:
                if span["parent_span_id"] == binascii.a2b_hex("0000000000000000"):
                    self.assertEqual(binascii.a2b_hex(spanID), span["span_id"])
                    break


class TestOpenTelemetryTracingBaseYAML(DNSDistOpenTelemetryProtobufBaseTest):
    _yaml_config_params = [
        "_testServerPort",
        "_protobufServerPort",
    ]
    _yaml_config_template = """---
logging:
  open_telemetry_tracing: true

backends:
  - address: 127.0.0.1:%d
    protocol: Do53

remote_logging:
 protobuf_loggers:
   - name: pblog
     address: 127.0.0.1:%d

query_rules:
 - name: Enable tracing
   selector:
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
"""

    def testBasic(self):
        self.doTest()

    def testTCP(self):
        self.doTest(useTCP=True)


class TestOpenTelemetryTracingBaseLua(DNSDistOpenTelemetryProtobufBaseTest):
    _config_params = [
        "_testServerPort",
        "_protobufServerPort",
    ]

    _config_template = """
newServer{address="127.0.0.1:%d"}
rl = newRemoteLogger('127.0.0.1:%d')
setOpenTelemetryTracing(true)

addAction(AllRule(), SetTraceAction(true), {name="Enable tracing"})
addResponseAction(AllRule(), RemoteLogResponseAction(rl), {name="Do PB logging"})
"""

    def testBasic(self):
        self.doTest()

    def testTCP(self):
        self.doTest(useTCP=True)


class TestOpenTelemetryTracingBaseDelayYAML(DNSDistOpenTelemetryProtobufBaseTest):
    _yaml_config_params = [
        "_testServerPort",
        "_protobufServerPort",
    ]
    _yaml_config_template = """---
logging:
  open_telemetry_tracing: true

backends:
  - address: 127.0.0.1:%d
    protocol: Do53

remote_logging:
 protobuf_loggers:
   - name: pblog
     address: 127.0.0.1:%d

query_rules:
 - name: Enable tracing
   selector:
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
     delay: true
"""

    def testBasic(self):
        self.doTest(True)

    def testTCP(self):
        self.doTest(wasDelayed=True, useTCP=True)


class TestOpenTelemetryTracingBaseDelayLua(DNSDistOpenTelemetryProtobufBaseTest):
    _config_params = [
        "_testServerPort",
        "_protobufServerPort",
    ]

    _config_template = """
newServer{address="127.0.0.1:%d"}
rl = newRemoteLogger('127.0.0.1:%d')
setOpenTelemetryTracing(true)

addAction(AllRule(), SetTraceAction(true), {name="Enable tracing"})
addResponseAction(AllRule(), RemoteLogResponseAction(rl, nil, false, {}, {}, true), {name="Do PB logging"})
"""

    def testBasic(self):
        self.doTest(True)

    def testTCP(self):
        self.doTest(wasDelayed=True, useTCP=True)


class TestOpenTelemetryTracingUseIncomingYAML(DNSDistOpenTelemetryProtobufBaseTest):
    _yaml_config_params = [
        "_testServerPort",
        "_protobufServerPort",
    ]
    _yaml_config_template = """---
logging:
  open_telemetry_tracing: true

backends:
  - address: 127.0.0.1:%d
    protocol: Do53

remote_logging:
 protobuf_loggers:
   - name: pblog
     address: 127.0.0.1:%d

query_rules:
 - name: Enable tracing
   selector:
     type: All
   action:
     type: SetTrace
     value: true
     use_incoming_traceid: true

response_rules:
 - name: Do PB logging
   selector:
     type: All
   action:
     type: RemoteLog
     logger_name: pblog
"""

    def testNoTraceID(self):
        self.doTest()

    def testOnlyTraceID(self):
        self.doTest(traceID="0123456789ABCDEF0123456789ABCDEF")

    def testTraceIDAndSpanID(self):
        self.doTest(
            traceID="0123456789ABCDEF0123456789ABCDEF",
            spanID="FEDCBA9876543210",
        )


class TestOpenTelemetryTracingUseIncomingLua(DNSDistOpenTelemetryProtobufBaseTest):
    _config_params = [
        "_testServerPort",
        "_protobufServerPort",
    ]
    _config_template = """
newServer{address="127.0.0.1:%d"}
rl = newRemoteLogger('127.0.0.1:%d')
setOpenTelemetryTracing(true)

addAction(AllRule(), SetTraceAction(true, true), {name="Enable tracing"})
addResponseAction(AllRule(), RemoteLogResponseAction(rl, nil, false, {}, {}, false), {name="Do PB logging"})
"""

    def testNoTraceID(self):
        self.doTest()

    def testOnlyTraceID(self):
        self.doTest(traceID="0123456789ABCDEF0123456789ABCDEF")

    def testTraceIDAndSpanID(self):
        self.doTest(
            traceID="0123456789ABCDEF0123456789ABCDEF",
            spanID="FEDCBA9876543210",
        )


class DNSDistOpenTelemetryProtobufNoOTDataTest(DNSDistOpenTelemetryProtobufTest):
    def doTest(self):
        msg = self.sendQueryAndGetProtobuf()

        self.assertFalse(msg.HasField("openTelemetryTraceID"))
        self.assertFalse(msg.HasField("openTelemetryData"))


class DNSDistOpenTelemetryProtobufEnabledButUnsetYAML(
    DNSDistOpenTelemetryProtobufNoOTDataTest
):
    _yaml_config_params = ["_testServerPort", "_protobufServerPort"]
    _yaml_config_template = """---

logging:
  open_telemetry_tracing: true

backends:
  - address: 127.0.0.1:%d
    protocol: Do53

remote_logging:
 protobuf_loggers:
   - name: pblog
     address: 127.0.0.1:%d

response_rules:
 - name: Do PB logging
   selector:
     type: All
   action:
     type: RemoteLog
     logger_name: pblog
"""

    def testEnabledButUnset(self):
        self.doTest()


class DNSDistOpenTelemetryProtobufEnabledButUnsetLua(
    DNSDistOpenTelemetryProtobufNoOTDataTest
):
    _config_params = ["_testServerPort", "_protobufServerPort"]
    _config_template = """
newServer{address="127.0.0.1:%d"}
rl = newRemoteLogger('127.0.0.1:%d')
setOpenTelemetryTracing(true)

addResponseAction(AllRule(), RemoteLogResponseAction(rl))
"""

    def testEnabledButUnset(self):
        self.doTest()


class DNSDistOpenTelemetryProtobufEnabledSetButTurnedOffYAML(
    DNSDistOpenTelemetryProtobufNoOTDataTest
):
    """Here we turn tracing on for the query, only to disable it after that"""

    _yaml_config_params = ["_testServerPort", "_protobufServerPort"]

    _yaml_config_template = """---
logging:
  open_telemetry_tracing: true

backends:
  - address: 127.0.0.1:%d
    protocol: Do53

remote_logging:
 protobuf_loggers:
   - name: pblog
     address: 127.0.0.1:%d

query_rules:
 - name: Enable tracing
   selector:
     type: All
   action:
     type: SetTrace
     value: true
 - name: Enable tracing
   selector:
     type: All
   action:
     type: SetTrace
     value: false

response_rules:
 - name: Do PB logging
   selector:
     type: All
   action:
     type: RemoteLog
     logger_name: pblog
"""

    def testDisabledAfterEnabled(self):
        self.doTest()


class DNSDistOpenTelemetryProtobufEnabledSetButTurnedOffLua(
    DNSDistOpenTelemetryProtobufNoOTDataTest
):
    _config_params = ["_testServerPort", "_protobufServerPort"]
    _config_template = """
newServer{address="127.0.0.1:%d"}
rl = newRemoteLogger('127.0.0.1:%d')
setOpenTelemetryTracing(true)

addAction(AllRule(), SetTraceAction(true))
addAction(AllRule(), SetTraceAction(false))
addResponseAction(AllRule(), RemoteLogResponseAction(rl))
"""

    def testEnabledButUnset(self):
        self.doTest()
