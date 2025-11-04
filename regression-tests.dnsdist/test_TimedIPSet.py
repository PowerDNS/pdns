#!/usr/bin/env python
import base64
import time
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestTimeIPSetYaml(DNSDistTest):

    _yaml_config_template = """---
console:
  listen_address: "127.0.0.1:%d"
  key: "%s"
  acl:
    - 127.0.0.0/8

binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

timed_ip_sets:
  - name: "my-set"

query_rules:
  - name: "refuse names in the Timed IP set"
    selector:
      type: "TimedIPSet"
      set_name: "my-set"
    action:
      type: "RCode"
      rcode: "Refused"
"""
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _consolePort = pickAvailablePort()
    _testServerPort = pickAvailablePort()
    _yaml_config_params = ['_consolePort', '_consoleKeyB64', '_dnsDistPort', '_testServerPort']
    _config_params = []

    def testTimedIPSet(self):
        """
        TimedIPSet from YAML configuration
        """
        name = 'timedipset-yaml.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        refusedResponse = dns.message.make_response(query)
        refusedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ["sendUDPQuery", "sendTCPQuery"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)

        # now we block it for one second
        self.sendConsoleCommand('getObjectFromYAMLConfiguration(\'my-set\'):add(newCA(\'127.0.0.1\'), 1)')

        for method in ["sendUDPQuery", "sendTCPQuery"]:
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, refusedResponse)

        time.sleep(1)

        # should be unblocked now
        for method in ["sendUDPQuery", "sendTCPQuery"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)

class TestTimeIPSetLua(DNSDistTest):
    _config_template = """---
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}

    mySet = TimedIPSetRule()
    addAction(mySet:slice(), RCodeAction(DNSRCode.REFUSED))
"""
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _consolePort = pickAvailablePort()
    _testServerPort = pickAvailablePort()
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']

    def testTimedIPSet(self):
        """
        TimedIPSet from Lua configuration
        """
        name = 'timedipset-lua.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        refusedResponse = dns.message.make_response(query)
        refusedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ["sendUDPQuery", "sendTCPQuery"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)

        # now we block it for one second
        self.sendConsoleCommand('mySet:add(newCA(\'127.0.0.1\'), 1)')

        for method in ["sendUDPQuery", "sendTCPQuery"]:
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, refusedResponse)

        time.sleep(1)

        # should be unblocked now
        for method in ["sendUDPQuery", "sendTCPQuery"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)
