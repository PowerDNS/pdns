#!/usr/bin/env python
import base64
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestYaml(DNSDistTest):

    _yaml_config_template = """---
webserver:
  listen-address: "127.0.0.1:%d"
  acl:
    - 127.0.0.0/8

console:
  listen-address: "127.0.0.1:%d"
  key: "%s"
  acl:
    - 127.0.0.0/8

edns-client-subnet:
  override-existing: true
  source-prefix-v4: 32
  source-prefix-v6: 48

acl:
  - 127.0.0.1/32
  - ::1/128

ring-buffers:
  size: 2000
  shards: 2

binds:
  - listen-address: "127.0.0.1:%d"
    reuseport: true
    protocol: Do53
    threads: 2

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53
    pools:
      - "tcp-pool"
      - "inline"

pools:
  - name: "tcp-pool"
    policy: "leastoutstanding"

selectors:
  - type: "TCP"
    name: "is-tcp"
    tcp: true

query-rules:
  - name: "route inline-yaml to inline pool"
    selector:
      type: "QNameSet"
      qnames:
        - "inline-lua.yaml.test.powerdns.com."
    action:
      type: "Pool"
      pool-name: "inline"
      stop-processing: true
  - name: "my-rule"
    selector:
      type: "And"
      selectors:
        - type: "ByName"
          selector-name: "is-tcp"
        - type: "Not"
          selector:
            type: "RD"
    action:
      type: "Pool"
      pool-name: "tcp-pool"

response-rules:
  - name: "inline RD=0 TCP gets cleared"
    selector:
      type: "And"
      selectors:
        - type: "ByName"
          selector-name: "is-tcp"
        - type: "QNameSet"
          qnames:
            - "inline-lua.yaml.test.powerdns.com."
        - type: "Lua"
          name: "Match responses on RD=0 (inline)"
          function-code: |
            return function(dr)
              local rd = dr.dh:getRD()
              if not rd then
                return true
              end
              return false
            end
    action:
      type: "ClearRecordTypes"
      types:
        - 1
  - name: "inline RD=0 UDP gets truncated"
    selector:
      type: "And"
      selectors:
        - type: "QNameSet"
          qnames:
            - "inline-lua.yaml.test.powerdns.com."
        - type: "Lua"
          name: "Match responses on RD=0 (file)"
          function-file: "yaml-config-files/yaml-inline-lua-file.yml"
    action:
      type: "TC"
"""
    _webServerPort = pickAvailablePort()
    _dnsDistPort = pickAvailablePort()
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _consolePort = pickAvailablePort()
    _testServerPort = pickAvailablePort()
    _yaml_config_params = ['_webServerPort', '_consolePort', '_consoleKeyB64', '_dnsDistPort', '_testServerPort']
    _config_params = []

    def testForwarded(self):
        """
        Yaml: Forwarded query
        """
        name = 'forwarded.yaml.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        # UDP query should be dropped
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)
        # TCP query should be forwarded
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response=response)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

    def testInlineLua(self):
        """
        Yaml: Inline Lua
        """
        name = 'inline-lua.yaml.test.powerdns.com.'

        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)
        truncatedResponse = dns.message.make_response(query)
        truncatedResponse.flags |= dns.flags.TC
        clearedResponse = dns.message.make_response(query)

        # UDP response without RD should be truncated
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response=response)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, truncatedResponse)

        # TCP response should have its A records cleared
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response=response)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, clearedResponse)

        # response with RD should be forwarded
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags |= dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)
        for method in ["sendUDPQuery", "sendTCPQuery"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)
