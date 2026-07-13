#!/usr/bin/env python
import base64
import threading
import clientsubnetoption
import dns
from dnsdisttests import DNSDistTest, Queue, pickAvailablePort
from proxyprotocolutils import ProxyProtocolUDPResponder


class TeeActionBase(object):
    _teeServerPort = pickAvailablePort()
    _teeProxyServerPort = pickAvailablePort()
    _toTeeQueue = Queue()
    _fromTeeQueue = Queue()
    _toTeeProxyQueue = Queue()
    _fromTeeProxyQueue = Queue()

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

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
            args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, True],
        )
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

        cls._TeeResponder = threading.Thread(
            name="Tee Responder", target=cls.UDPResponder, args=[cls._teeServerPort, cls._toTeeQueue, cls._fromTeeQueue]
        )
        cls._TeeResponder.daemon = True
        cls._TeeResponder.start()

        cls._TeeProxyResponder = threading.Thread(
            name="Proxy Protocol Tee Responder",
            target=ProxyProtocolUDPResponder,
            args=[cls._teeProxyServerPort, cls._toTeeProxyQueue, cls._fromTeeProxyQueue],
        )
        cls._TeeProxyResponder.daemon = True
        cls._TeeProxyResponder.start()

    def testTeeWithECS(self):
        """
        TeeAction: ECS
        """
        name = "ecs.tee.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)

        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.answer.append(rrset)

        numberOfQueries = 10
        for _ in range(numberOfQueries):
            # push the response to the Tee server
            self._toTeeQueue.put(response, True, 2.0)

            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

            # retrieve the query from the Tee server
            teedQuery = self._fromTeeQueue.get(True, 2.0)
            ecso = clientsubnetoption.ClientSubnetOption("127.0.0.1", 24)
            expectedQuery = dns.message.make_query(name, "A", "IN", use_edns=True, options=[ecso], payload=512)
            expectedQuery.id = query.id
            self.checkQueryEDNSWithECS(expectedQuery, teedQuery)

        # check the TeeAction stats
        stats = self.sendConsoleCommand("getAction(0):printStats()")
        self.assertEqual(
            stats,
            """noerrors\t%d
nxdomains\t0
other-rcode\t0
queries\t%d
recv-errors\t0
refuseds\t0
responses\t%d
send-errors\t0
servfails\t0
tcp-drops\t0
"""
            % (numberOfQueries, numberOfQueries, numberOfQueries),
        )

    def testTeeWithoutECS(self):
        """
        TeeAction: No ECS
        """
        name = "noecs.tee.tests.powerdns.com."
        query = dns.message.make_query(name, "AAAA", "IN")
        response = dns.message.make_response(query)

        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:DB8::1")
        response.answer.append(rrset)

        numberOfQueries = 10
        for _ in range(numberOfQueries):
            # push the response to the Tee server
            self._toTeeQueue.put(response, True, 2.0)

            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

            # retrieve the query from the Tee server
            teedQuery = self._fromTeeQueue.get(True, 2.0)
            ecso = clientsubnetoption.ClientSubnetOption("127.0.0.1", 24)
            expectedQuery = dns.message.make_query(name, "AAAA", "IN", use_edns=True, options=[ecso], payload=512)
            expectedQuery.id = query.id
            self.checkMessageNoEDNS(expectedQuery, teedQuery)

        # check the TeeAction stats
        stats = self.sendConsoleCommand("getAction(0):printStats()")
        self.assertEqual(
            stats,
            """noerrors\t%d
nxdomains\t0
other-rcode\t0
queries\t%d
recv-errors\t0
refuseds\t0
responses\t%d
send-errors\t0
servfails\t0
tcp-drops\t0
"""
            % (numberOfQueries, numberOfQueries, numberOfQueries),
        )

    def testTeeWithProxy(self):
        """
        TeeAction: Proxy
        """
        name = "proxy.tee.tests.powerdns.com."
        query = dns.message.make_query(name, "ANY", "IN")
        response = dns.message.make_response(query)

        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.answer.append(rrset)

        numberOfQueries = 10
        for _ in range(numberOfQueries):
            # push the response to the Tee Proxy server
            self._toTeeProxyQueue.put(response, True, 2.0)

            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

            # retrieve the query from the Tee Proxy server
            [payload, teedQuery] = self._fromTeeProxyQueue.get(True, 2.0)
            self.checkMessageNoEDNS(query, dns.message.from_wire(teedQuery))
            self.checkMessageProxyProtocol(payload, "127.0.0.1", "127.0.0.1", False)

        # check the TeeAction stats
        stats = self.sendConsoleCommand("getAction(0):printStats()")
        self.assertEqual(
            stats,
            """noerrors\t%d
nxdomains\t0
other-rcode\t0
queries\t%d
recv-errors\t0
refuseds\t0
responses\t%d
send-errors\t0
servfails\t0
tcp-drops\t0
"""
            % (numberOfQueries, numberOfQueries, numberOfQueries),
        )

class TestTeeActionLua(TeeActionBase, DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _teeServerPort = pickAvailablePort()
    _teeProxyServerPort = pickAvailablePort()
    _toTeeQueue = Queue()
    _fromTeeQueue = Queue()
    _toTeeProxyQueue = Queue()
    _fromTeeProxyQueue = Queue()
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    addAction(QTypeRule(DNSQType.A), TeeAction("127.0.0.1:%d", true))
    addAction(QTypeRule(DNSQType.AAAA), TeeAction("127.0.0.1:%d", false))
    addAction(QTypeRule(DNSQType.ANY), TeeAction("127.0.0.1:%d", false, '127.0.0.1', true))
    """
    _config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_testServerPort",
        "_teeServerPort",
        "_teeServerPort",
        "_teeProxyServerPort",
    ]

class TestTeeActionYaml(TeeActionBase, DNSDistTest):
    _yaml_config_template = """---
console:
  listen_address: "127.0.0.1:%d"
  key: "%s"
  acl:
    - 127.0.0.0/8

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

query_rules:
  - name: "A to ECS Tee Action"
    selector:
      type: "QType"
      qtype: "A"
    action:
      type: "Tee"
      rca: "127.0.0.1:%d"
      lca: ""
      add_ecs: true
  - name: "AAAA to no-ECS Tee Action"
    selector:
      type: "QType"
      qtype: "AAAA"
    action:
      type: "Tee"
      rca: "127.0.0.1:%d"
      add_ecs: false
  - name: "ANY to Proxy Protocol Tee Action"
    selector:
      type: "QType"
      qtype: "ANY"
    action:
      type: "Tee"
      rca: "127.0.0.1:%d"
      lca: "127.0.0.1"
      add_ecs: false
      add_proxy_protocol: true
"""
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _consolePort = pickAvailablePort()
    _yaml_config_params = [
        "_consolePort",
        "_consoleKeyB64",
        "_testServerPort",
        "_teeServerPort",
        "_teeServerPort",
        "_teeProxyServerPort",
    ]
    _config_params = [
    ]
