import http.server
import threading
import time

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import google.protobuf.json_format
import opentelemetry.proto.collector.trace.v1.trace_service_pb2

from dnsdisttests import DNSDistTest, Queue, pickAvailablePort


class OTLPRequestHandler(http.server.BaseHTTPRequestHandler):
    queue = Queue()

    def __init__(self, queue: Queue, *args):
        self.queue = queue
        super().__init__(*args)

    def do_POST(self):
        if self.path != "/v1/traces":
            self.send_error(http.HTTPStatus.NOT_FOUND)
            return

        ctypeHdr = self.headers.get("Content-Type")
        if ctypeHdr is None or ctypeHdr != "application/x-protobuf":
            self.send_error(http.HTTPStatus.BAD_REQUEST, "I need protobuf")
            return

        content_length = int(self.headers.get("Content-Length", 0))

        if content_length == 0:
            self.send_error(http.HTTPStatus.BAD_REQUEST, "No data in request")

        body = self.rfile.read(content_length)

        messages = opentelemetry.proto.collector.trace.v1.trace_service_pb2.ExportTraceServiceRequest()
        messages.ParseFromString(body)

        # Let the client know we succesfully received their traces
        response = opentelemetry.proto.collector.trace.v1.trace_service_pb2.ExportTraceServiceResponse()
        response.partial_success.rejected_spans = 0
        self.send_response(http.HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(response.SerializeToString())

        for span in messages.resource_spans:
            rs_data = google.protobuf.json_format.MessageToDict(span, preserving_proto_field_name=True)
            print(rs_data)
            self.queue.put(rs_data, True, timeout=2.0)


class OTLPServer:
    def __init__(self, port, queue) -> None:
        def handler(*args):
            return OTLPRequestHandler(queue, *args)

        server = http.server.HTTPServer(("127.0.0.1", port), handler)
        server.serve_forever()


class DNSDistOtlpTest(DNSDistTest):
    _otlpServerPort = pickAvailablePort()
    _otlpQueue = Queue()
    _otlpServer = None

    @classmethod
    def startResponders(cls):
        cls._UDPResponder = threading.Thread(
            name="UDP Responder",
            target=cls.UDPResponder,
            args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue],
        )
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()

        cls._TCPResponder = threading.Thread(
            name="TCP Responder",
            target=cls.TCPResponder,
            args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue],
        )
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

        cls._otlpServer = threading.Thread(
            name="OTLP server", target=OTLPServer, args=[cls._otlpServerPort, cls._otlpQueue]
        )
        cls._otlpServer.daemon = True
        cls._otlpServer.start()

    def getFirstResourceSpan(self, timeout=None):
        if timeout is not None:
            self.waitUntilQueueIsNoLongerEmpty(timeout)
        self.assertFalse(self._otlpQueue.empty())
        data = self._otlpQueue.get(False)
        self.assertTrue(data)
        return data

    def waitUntilQueueIsNoLongerEmpty(self, timeout=1):
        remaining = timeout * 1000  # milliseconds
        while self._otlpQueue.empty() and remaining > 0:
            time.sleep(0.01)
            remaining -= 10

    def sendQueryAndGetResourceSpan(self, useTCP=False):
        name = "query.ot.tests.powerdns.com."

        target = "target.ot.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)

        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.CNAME, target)
        response.answer.append(rrset)

        rrset = dns.rrset.from_text(target, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)

        if useTCP:
            self.sendTCPQuery(query, response)
        else:
            self.sendUDPQuery(query, response)

        # check the protobuf message corresponding to the UDP query
        return self.getFirstResourceSpan(timeout=2)


class TestDNSDistOtlpYAML(DNSDistOtlpTest):
    # We're not testing the _content_ of the traces, as those are tested in test_OpenTelemetryTracing.py.
    # These tests are mostly to verify that the OTLP exporter sends us proper data

    _yaml_config_params = [
        "_testServerPort",
        "_otlpServerPort",
    ]
    _yaml_config_template = """---
logging:
  open_telemetry_tracing:
    enabled: true

backends:
  - address: 127.0.0.1:%d
    protocol: Do53
    health_checks:
      mode: up

remote_logging:
  otlp_loggers:
   - name: otlplog
     address: http://127.0.0.1:%d/v1/traces
     interval: 1

query_rules:
 - name: Enable tracing
   selector:
     type: All
   action:
     type: SetTrace
     value: true
     remote_loggers:
       - otlplog
"""

    def testUDP(self):
        print(self._otlpServerPort)
        self.sendQueryAndGetResourceSpan()

    def testTCP(self):
        print(self._otlpServerPort)
        self.sendQueryAndGetResourceSpan(useTCP=True)


class TestDNSDistOtlpLua(TestDNSDistOtlpYAML):
    # We're not testing the _content_ of the traces, as those are tested in test_OpenTelemetryTracing.py.
    # These tests are mostly to verify that the OTLP exporter sends us proper data

    _otlpServerPort = pickAvailablePort()
    _yaml_config_params = None
    _yaml_config_template = None
    _config_params = [
        "_testServerPort",
        "_otlpServerPort",
    ]
    _config_template = """
setOpenTelemetryTracing(true)
newServer{address="127.0.0.1:%d"}
getServer(0):setUp()

otlpLogger = newOtlpLogger('http://127.0.0.1:%d/v1/traces', {interval=1})
addAction(AllRule(), SetTraceAction(true, {remoteLoggers={otlpLogger}}), {name="Enable tracing"})
"""
