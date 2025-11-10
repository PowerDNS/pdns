#!/usr/bin/env python
import base64
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestYaml(DNSDistTest):

    _yaml_config_template = """---
webserver:
  listen_addresses:
    - "127.0.0.2:%d"
    - "127.0.0.1:%d"
  acl:
    - 127.0.0.0/8

console:
  listen_address: "127.0.0.1:%d"
  key: "%s"
  acl:
    - 127.0.0.0/8

edns_client_subnet:
  override_existing: true
  source_prefix_v4: 32
  source_prefix_v6: 48

acl:
  - 127.0.0.1/32
  - ::1/128

ring_buffers:
  size: 2000
  shards: 2

binds:
  - listen_address: "127.0.0.1:%d"
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
    policy: "leastOutstanding"

selectors:
  - type: "TCP"
    name: "is-tcp"
    tcp: true

query_rules:
  - name: "route inline-yaml to inline pool"
    selector:
      type: "QNameSet"
      qnames:
        - "inline-lua.yaml.test.powerdns.com."
    action:
      type: "Pool"
      pool_name: "inline"
      stop_processing: true
  - name: "my-rule"
    selector:
      type: "And"
      selectors:
        - type: "ByName"
          selector_name: "is-tcp"
        - type: "Not"
          selector:
            type: "RD"
    action:
      type: "Pool"
      pool_name: "tcp-pool"

response_rules:
  - name: "inline RD=0 TCP gets cleared"
    selector:
      type: "And"
      selectors:
        - type: "ByName"
          selector_name: "is-tcp"
        - type: "QNameSet"
          qnames:
            - "inline-lua.yaml.test.powerdns.com."
        - type: "Lua"
          name: "Match responses on RD=0 (inline)"
          function_code: |
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
          function_file: "yaml-config-files/yaml-inline-lua-file.yml"
    action:
      type: "TC"
"""
    _webServerPort = pickAvailablePort()
    _webServerPort2 = pickAvailablePort()
    _dnsDistPort = pickAvailablePort()
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _consolePort = pickAvailablePort()
    _testServerPort = pickAvailablePort()
    _yaml_config_params = ['_webServerPort', '_webServerPort2', '_consolePort', '_consoleKeyB64', '_dnsDistPort', '_testServerPort']
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

class TestMixingYamlWithLua(DNSDistTest):

    _yaml_config_template = """---
binds:
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: Do53
    threads: 2

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53
    pools:
      - "tcp-pool"
      - "inline"
query_rules:
  - name: "refused"
    selector:
      type: "QNameSet"
      qnames:
        - "refused.yaml-lua-mix.test.powerdns.com."
    action:
      type: "RCode"
      rcode: "Refused"

"""
    _dnsDistPort = pickAvailablePort()
    _testServerPort = pickAvailablePort()
    _yaml_config_params = ['_dnsDistPort', '_testServerPort']
    _config_params = []
    _config_template = """
enableLuaConfiguration()
addAction(QNameRule("notimp-lua.yaml-lua-mix.test.powerdns.com."), RCodeAction(DNSRCode.NOTIMP))
"""

    def testRefusedFromYAML(self):
        """
        Yaml / Lua mix: Refused from YAML
        """
        name = 'refused.yaml-lua-mix.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)
        for method in ["sendUDPQuery", "sendTCPQuery"]:
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

    def testNotImpFromLua(self):
        """
        Yaml / Lua mix: Not imp from Lua
        """
        name = 'notimp-lua.yaml-lua-mix.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)
        for method in ["sendUDPQuery", "sendTCPQuery"]:
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestYamlNMGRule(DNSDistTest):

    _yaml_config_template = """---
binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

query_rules:
  - name: "refuse queries from non-allowed netmasks"
    selector:
      type: "Not"
      selector:
        type: "NetmaskGroup"
        netmasks:
          - "192.0.2.1/32"
    action:
      type: "RCode"
      rcode: "5"
"""
    _yaml_config_params = ['_dnsDistPort', '_testServerPort']
    _config_params = []

    def testYamlNMGRule(self):
        """
        YAML: NMGRule should refuse our queries
        """
        name = 'nmgrule.yaml.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestYamlNMGRule(DNSDistTest):

    _yaml_config_template = """---
binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

query_rules:
  - name: "refuse queries from non-allowed netmasks"
    selector:
      type: "Not"
      selector:
        type: "NetmaskGroup"
        netmasks:
          - "192.0.2.1/32"
    action:
      type: "RCode"
      rcode: "5"
"""
    _yaml_config_params = ['_dnsDistPort', '_testServerPort']
    _config_params = []

    def testYamlNMGRule(self):
        """
        YAML: NMGRule should refuse our queries
        """
        name = 'nmgrule.yaml.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestYamlNMGRuleObject(DNSDistTest):

    _yaml_config_template = """---
binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

netmask_groups:
  - name: "my-mng"
    netmasks:
      - "192.0.2.1/32"
      - "127.0.0.1/32"

query_rules:
  - name: "refuse queries from specific netmasks"
    selector:
      type: "NetmaskGroup"
      netmask_group_name: "my-mng"
    action:
      type: "RCode"
      rcode: "5"
"""
    _yaml_config_params = ['_dnsDistPort', '_testServerPort']
    _config_params = []

    def testYamlNMGRule(self):
        """
        YAML: NMGRule (via a NMG object) should refuse our queries
        """
        name = 'nmgrule-object.yaml.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestYamlOpcode(DNSDistTest):

    _yaml_config_template = """---
binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

query_rules:
  - name: "refuse queries from specific opcode"
    selector:
      type: "Opcode"
      code: "NOTIFY"
    action:
      type: "RCode"
      rcode: "Refused"
"""
    _yaml_config_params = ['_dnsDistPort', '_testServerPort']
    _config_params = []

    def testRefuseOpcodeNotify(self):
        """
        YAML: Refuse Opcode NOTIFY
        """
        name = 'opcodenotify.yaml.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.set_opcode(dns.opcode.NOTIFY)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

    def testAllowOpcodeUpdate(self):
        """
        YAML: Allow Opcode UPDATE
        """
        name = 'opcodeupdate.yaml.tests.powerdns.com.'
        query = dns.message.make_query(name, 'SOA', 'IN')
        query.set_opcode(dns.opcode.UPDATE)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

class TestYamlUnknownSelectorName(DNSDistTest):

    _yaml_config_template = """---
binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

query_rules:
  - name: "my-rule"
    selector:
      type: "And"
      selectors:
        - type: "ByName"
          selector_name: "is-tcp"
        - type: "Not"
          selector:
            type: "RD"
    action:
      type: "Pool"
      pool_name: "tcp-pool"
"""
    _yaml_config_params = ['_dnsDistPort', '_testServerPort']
    _config_params = []

    def testFailToStart(self):
        """
        YAML: Fails to start with unknown selector name
        """
        pass

    @classmethod
    def setUpClass(cls):
        failed = False
        try:
            cls.startDNSDist()
        except AssertionError as err:
            failed = True
            expected = "dnsdist --check-config failed (1): b'Error while parsing YAML file configs/dnsdist_TestYamlUnknownSelectorName.yml: Unable find a selector named is-tcp\\n'"
            if str(err) != expected:
                raise AssertionError("DNSdist should not start with an unknown selector name: %s" % (err))
        if not failed:
            raise AssertionError("DNSdist should not start with an unknown selector name")

    @classmethod
    def tearDownClass(cls):
        if cls._dnsdist:
            cls.killProcess(cls._dnsdist)
