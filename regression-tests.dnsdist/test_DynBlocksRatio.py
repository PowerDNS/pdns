#!/usr/bin/env python
import base64
import socket
import time
import dns
from dnsdistDynBlockTests import DynBlocksTest, waitForMaintenanceToRun
from dnsdisttests import pickAvailablePort

class TestDynBlockGroupServFailsRatio(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio
        """
        name = 'servfailratio.group.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRatio(name, dns.rcode.SERVFAIL, 10, 10)

class TestDynBlockGroupServFailsRatioDoH(DynBlocksTest):
    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _dnsDistListeningAddr = "127.0.0.2"
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _webSevrerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKey = 'apisecret'
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    addDOHLocal("%s:%d", "%s", "%s", { "/" }, {trustForwardedForHeader=true})
    setACL({'127.0.0.1', '192.0.2.1/32'})

    newServer{address="127.0.0.1:%d"}

    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_dnsDistListeningAddr', '_dohServerPort', '_serverCert', '_serverKey', '_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio via DoH
        """
        name = 'rcode-servfailratio-doh.group.dynblocks.tests.powerdns.com.'
        rcodeQuery = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(rcodeQuery)
        expectedResponse.set_rcode(dns.rcode.SERVFAIL)

        rcodecount = 20
        sent = 0
        allowed = 0
        for _ in range(rcodecount):
            (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, rcodeQuery, response=expectedResponse, caFile=self._caCert, customHeaders=['x-forwarded-for: 192.0.2.1'])

            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = rcodeQuery.id
                self.assertEqual(rcodeQuery, receivedQuery)
                self.assertEqual(expectedResponse, receivedResponse)
                allowed = allowed + 1
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we should have been able to send all our queries since the minimum number of queries is set to noerrorcount + rcodecount
        self.assertGreaterEqual(allowed, rcodecount)

        waitForMaintenanceToRun()

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, rcodeQuery, response=None, caFile=self._caCert, customHeaders=['x-forwarded-for: 192.0.2.1'], useQueue=False, timeout=1)
        self.assertEqual(receivedResponse, None)

        self.doTestDynBlockViaAPI('192.0.2.1/32', 'Exceeded query rate', 1, self._dynBlockDuration, (sent-allowed)+1, (sent-allowed)+1, False)

class TestDynBlockGroupServFailsRatioDoHCacheHit(DynBlocksTest):
    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _dnsDistListeningAddr = "127.0.0.2"
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _webSevrerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKey = 'apisecret'
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    addDOHLocal("%s:%d", "%s", "%s", { "/" }, {trustForwardedForHeader=true})
    setACL({'127.0.0.1', '192.0.2.1/32'})

    pc = newPacketCache(1000, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)

    newServer{address="127.0.0.1:%d"}

    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_dnsDistListeningAddr', '_dohServerPort', '_serverCert', '_serverKey', '_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio via DoH (cache hits)
        """
        name = 'rcode-servfailratio-doh-cache-hits.group.dynblocks.tests.powerdns.com.'
        rcodeQuery = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(rcodeQuery)
        expectedResponse.set_rcode(dns.rcode.SERVFAIL)

        rcodecount = 20
        sent = 0
        allowed = 0
        firstQuery = True
        for _ in range(rcodecount):
            if firstQuery:
                (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, rcodeQuery, response=expectedResponse, caFile=self._caCert, customHeaders=['x-forwarded-for: 192.0.2.1'])
            else:
                (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, rcodeQuery, response=None, caFile=self._caCert, customHeaders=['x-forwarded-for: 192.0.2.1'], useQueue=False)

            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = rcodeQuery.id
                self.assertEqual(rcodeQuery, receivedQuery)
                self.assertEqual(expectedResponse, receivedResponse)
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()
            if receivedResponse:
                allowed = allowed + 1

        # we should have been able to send all our queries since the minimum number of queries is set to noerrorcount + rcodecount
        self.assertGreaterEqual(allowed, rcodecount)

        waitForMaintenanceToRun()

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, rcodeQuery, response=None, caFile=self._caCert, customHeaders=['x-forwarded-for: 192.0.2.1'], useQueue=False, timeout=1)
        self.assertEqual(receivedResponse, None)

        self.doTestDynBlockViaAPI('192.0.2.1/32', 'Exceeded query rate', 1, self._dynBlockDuration, (sent-allowed)+1, (sent-allowed)+1, False)

class TestDynBlockGroupServFailsRatioDoQ(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _dnsDistListeningAddr = "127.0.0.2"
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    addDOQLocal("%s:%d", "%s", "%s")
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_dnsDistListeningAddr', '_doqServerPort', '_serverCert', '_serverKey', '_testServerPort']

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio via DoQ
        """
        name = 'servfailratio-doq.group.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRatioViaProtocol(name, dns.rcode.SERVFAIL, 10, 10, "sendDOQQueryWrapper")

class TestDynBlockGroupServFailsRatioDoQCacheHit(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _dnsDistListeningAddr = "127.0.0.2"
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    local pc = newPacketCache(1000, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)

    addDOQLocal("%s:%d", "%s", "%s")
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_dnsDistListeningAddr', '_doqServerPort', '_serverCert', '_serverKey', '_testServerPort']

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio via DoQ (cache hits)
        """
        name = 'servfailratio-doq-hits.group.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRatioViaProtocol(name, dns.rcode.SERVFAIL, 10, 10, "sendDOQQueryWrapper", cached=True)

class TestDynBlockGroupServFailsRatioDoH3(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _dnsDistListeningAddr = "127.0.0.2"
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doh3ServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _doh3ServerPort))
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    addDOH3Local("%s:%d", "%s", "%s")
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_dnsDistListeningAddr', '_doh3ServerPort', '_serverCert', '_serverKey', '_testServerPort']

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio via DoH3
        """
        name = 'servfailratio-doh3.group.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRatioViaProtocol(name, dns.rcode.SERVFAIL, 10, 10, "sendDOH3QueryWrapper")

class TestDynBlockGroupServFailsRatioDoH3CacheHit(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _dnsDistListeningAddr = "127.0.0.2"
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doh3ServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _doh3ServerPort))
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    local pc = newPacketCache(1000, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)

    addDOH3Local("%s:%d", "%s", "%s")
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_dnsDistListeningAddr', '_doh3ServerPort', '_serverCert', '_serverKey', '_testServerPort']

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio via DoH3 (cache hits)
        """
        name = 'servfailratio-doh3-hits.group.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRatioViaProtocol(name, dns.rcode.SERVFAIL, 10, 10, "sendDOH3QueryWrapper", cached=True)

class TestDynBlockGroupCacheMissRatio(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setCacheMissRatio(0.8, %d, "Exceeded cache miss ratio", %d, 20, 0.0)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    local pc = newPacketCache(1000, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """

    def testDynBlocksCacheMissRatio(self):
        """
        Dyn Blocks (group): Cache miss ratio
        """
        name = 'cachemissratio.group.dynblocks.tests.powerdns.com.'
        self.doTestCacheMissRatio(name, 3, 17)

class TestDynBlockGroupCacheMissRatioSetTag(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setCacheMissRatio(0.8, %d, "Exceeded cache miss ratio", %d, 20, 0.0, DNSAction.SetTag, 0.0, { tagName='dyn-miss-ratio', tagValue='hit' })

    -- check that the tag is set and query rules executed
    addAction(AndRule{QNameRule("test-query-rules.cachemissratio-settag.group.dynblocks.tests.powerdns.com."), TagRule('dyn-miss-ratio', 'hit')}, SpoofAction("192.0.2.2"))

    -- on a cache miss, and if the cache miss ratio threshold was exceeded, send a REFUSED response
    addCacheMissAction(TagRule('dyn-miss-ratio', 'hit'), RCodeAction(DNSRCode.REFUSED))

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    local pc = newPacketCache(1000, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """

    def testDynBlocksCacheMissRatio(self):
        """
        Dyn Blocks (group): Cache miss ratio with SetTag
        """
        name = 'cachemissratio-settag.group.dynblocks.tests.powerdns.com.'
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')

        cacheHits = 3
        cacheMisses = 17
        for idx in range(cacheMisses):
            query = dns.message.make_query(str(idx) + '.' + name, 'A', 'IN')
            response = dns.message.make_response(query)
            response.answer.append(rrset)
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        query = dns.message.make_query('0.' + name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.answer.append(rrset)
        for _ in range(cacheHits):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)

        waitForMaintenanceToRun()

        # we should now get REFUSED for cache misses for up to self._dynBlockDuration + self._dynBlockPeriod

        # cache miss
        query = dns.message.make_query(str(cacheMisses + 1) + '.' + name, 'A', 'IN')
        # dnsdist sets RA = RD for TC responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, expectedResponse)

        # but a cache hit should be OK
        query = dns.message.make_query('0.' + name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, expectedResponse)

        # this specific query will match the query rules before triggering a cache miss
        # so we can check that the tag is correctly set for query rules as well
        query = dns.message.make_query('test-query-rules.' + name, 'A', 'IN')
        # dnsdist sets RA = RD for TC responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        queryRulesRRset = dns.rrset.from_text('test-query-rules.' + name,
                                                60,
                                                dns.rdataclass.IN,
                                                dns.rdatatype.A,
                                                '192.0.2.2')
        expectedResponse.answer.append(queryRulesRRset)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, expectedResponse)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        query = dns.message.make_query(str(cacheMisses + 2) + '.' + name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.answer.append(rrset)
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
