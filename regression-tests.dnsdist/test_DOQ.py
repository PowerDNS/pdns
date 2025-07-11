#!/usr/bin/env python
import base64
import dns
import clientsubnetoption

from dnsdisttests import DNSDistTest
from dnsdisttests import pickAvailablePort
from doqclient import quic_bogus_query
from quictests import QUICTests, QUICWithCacheTests, QUICACLTests, QUICGetLocalAddressOnAnyBindTests, QUICXFRTests
import doqclient
from doqclient import quic_query

class TestDOQBogus(DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    """
    _config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey']

    def testDOQBogus(self):
        """
        DOQ: Test a bogus query (wrong packed length)
        """
        name = 'bogus.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0

        try:
            message = quic_bogus_query(query, '127.0.0.1', 2.0, self._doqServerPort, verify=self._caCert, server_hostname=self._serverName)
            self.assertFalse(True)
        except doqclient.StreamResetError as e :
            self.assertEqual(e.error, 2);

class TestDOQ(QUICTests, DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addAction("drop.doq.tests.powerdns.com.", DropAction())
    addAction("refused.doq.tests.powerdns.com.", RCodeAction(DNSRCode.REFUSED))
    addAction("spoof.doq.tests.powerdns.com.", SpoofAction("1.2.3.4"))
    addAction("no-backend.doq.tests.powerdns.com.", PoolAction('this-pool-has-no-backend'))

    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    """
    _config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey']

    def getQUICConnection(self):
        return self.getDOQConnection(self._doqServerPort, self._caCert)

    def sendQUICQuery(self, query, response=None, useQueue=True, connection=None):
        return self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, useQueue=useQueue, serverName=self._serverName, connection=connection)

class TestDOQYaml(QUICTests, DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = ""
    _config_params = []
    _yaml_config_template = """---
backends:
  - address: "127.0.0.1:%d"
    protocol: "Do53"
binds:
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: "DoQ"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
query_rules:
  - name: "Drop"
    selector:
      type: "QName"
      qname: "drop.doq.tests.powerdns.com."
    action:
      type: "Drop"
  - name: "Refused"
    selector:
      type: "QName"
      qname: "refused.doq.tests.powerdns.com."
    action:
      type: "RCode"
      rcode: "5"
  - name: "Spoof"
    selector:
      type: "QName"
      qname: "spoof.doq.tests.powerdns.com."
    action:
      type: "Spoof"
      ips:
        - "1.2.3.4"
  - name: "No backend"
    selector:
      type: "QName"
      qname: "no-backend.doq.tests.powerdns.com."
    action:
      type: "Pool"
      pool_name: "this-pool-has-no-backend"
    """
    _yaml_config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey']

    def getQUICConnection(self):
        return self.getDOQConnection(self._doqServerPort, self._caCert)

    def sendQUICQuery(self, query, response=None, useQueue=True, connection=None):
        return self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, useQueue=useQueue, serverName=self._serverName, connection=connection)

class TestDOQWithCache(QUICWithCacheTests, DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addDOQLocal("127.0.0.1:%d", "%s", "%s")

    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """
    _config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey']

    def getQUICConnection(self):
        return self.getDOQConnection(self._doqServerPort, self._caCert)

    def sendQUICQuery(self, query, response=None, useQueue=True, connection=None):
        return self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, useQueue=useQueue, serverName=self._serverName, connection=connection)

class TestDOQWithACL(QUICACLTests, DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    setACL("192.0.2.1/32")
    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    """
    _config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey']

    def getQUICConnection(self):
        return self.getDOQConnection(self._doqServerPort, self._caCert)

    def sendQUICQuery(self, query, response=None, useQueue=True, connection=None):
        return self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, useQueue=useQueue, serverName=self._serverName, connection=connection)

class TestDOQXFR(QUICXFRTests, DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d", tcpOnly=True}

    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    """
    _config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey']
    _verboseMode = True

    def getQUICConnection(self):
        return self.getDOQConnection(self._doqServerPort, self._caCert)

    def sendQUICQuery(self, query, response=None, useQueue=True, connection=None):
        return self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, useQueue=useQueue, serverName=self._serverName, connection=connection)

class TestDOQCertificateReloading(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server-doq.key'
    _serverCert = 'server-doq.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")

    newServer{address="127.0.0.1:%d"}

    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    """
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_doqServerPort','_serverCert', '_serverKey']

    @classmethod
    def setUpClass(cls):
        cls.generateNewCertificateAndKey('server-doq')
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

    def testCertificateReloaded(self):
        name = 'certificate-reload.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        (_, serial) = quic_query(query, '127.0.0.1', 0.5, self._doqServerPort, verify=self._caCert, server_hostname=self._serverName)

        self.generateNewCertificateAndKey('server-doq')
        self.sendConsoleCommand("reloadAllCertificates()")

        (_, secondSerial) = quic_query(query, '127.0.0.1', 0.5, self._doqServerPort, verify=self._caCert, server_hostname=self._serverName)
        # check that the serial is different
        self.assertNotEqual(serial, secondSerial)

class TestDOQGetLocalAddressOnAnyBind(QUICGetLocalAddressOnAnyBindTests, DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    function answerBasedOnLocalAddress(dq)
      local dest = tostring(dq.localaddr)
      local i, j = string.find(dest, "[0-9.]+")
      local addr = string.sub(dest, i, j)
      local dashAddr = string.gsub(addr, "[.]", "-")
      return DNSAction.Spoof, "address-was-"..dashAddr..".local-address-any.advanced.tests.powerdns.com."
    end
    addAction("local-address-any.quic.tests.powerdns.com.", LuaAction(answerBasedOnLocalAddress))
    newServer{address="127.0.0.1:%s"}
    addDOQLocal("0.0.0.0:%d", "%s", "%s")
    addDOQLocal("[::]:%d", "%s", "%s")
    """
    _config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey', '_doqServerPort','_serverCert', '_serverKey']
    _acl = ['127.0.0.1/32', '::1/128']
    _skipListeningOnCL = True

    def getQUICConnection(self):
        return self.getDOQConnection(self._doqServerPort, self._caCert)

    def sendQUICQuery(self, query, response=None, useQueue=True, connection=None):
        return self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, useQueue=useQueue, serverName=self._serverName, connection=connection)
