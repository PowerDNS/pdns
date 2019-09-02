import clientsubnetoption
import cookiesoption
import dns
import os
import threading
import time

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

from recursortests import RecursorTest

class GettagRecursorTest(RecursorTest):
    _confdir = 'LuaGettag'
    _config_template = """
    log-common-errors=yes
    gettag-needs-edns-options=yes
    """
    _lua_dns_script_file = """
    function gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp)

      local tags = {}
      local data = {}

      -- make sure we can pass data around to the other hooks
      data['canary'] = 'from-gettag'

      -- test that the remote addr is valid
      if remote:toString() ~= '127.0.0.1' then
        pdnslog("invalid remote")
        table.insert(tags, 'invalid remote '..remote:toString())
        return 1, tags, data
      end

      -- test that the local addr is valid
      if localip:toString() ~= '127.0.0.1' then
        pdnslog("invalid local")
        table.insert(tags, 'invalid local '..localip:toString())
        return 1, tags, data
      end

      if not ednssubnet:empty() then
         table.insert(tags, 'edns-subnet-'..ednssubnet:toString())
      end

      for k,v in pairs(ednsoptions) do
        table.insert(tags, 'ednsoption-'..k..'-count-'..v:count())
        local len = 0
        local values = v:getValues()
        for j,l in pairs(values) do
          len = len + l:len()

          -- check that the old interface (before 4.2.0) still works
          if j == 0 then
            if l:len() ~= v.size then
              table.insert(tags, 'size obtained via the old edns option interface does not match')
            end
            value = v:getContent()
            if value ~= l then
              table.insert(tags, 'content obtained via the old edns option interface does not match')
            end
          end
        end
        table.insert(tags, 'ednsoption-'..k..'-total-len-'..len)
      end

      if tcp then
        table.insert(tags, 'gettag-tcp')
      end

      -- test that tags are passed to other hooks
      table.insert(tags, qname:toString())
      table.insert(tags, 'gettag-qtype-'..qtype)

      return 0, tags, data
    end

    function preresolve(dq)

      -- test that we are getting the tags set by gettag()
      -- and also getting the correct qname
      local found = false
      for _, tag in pairs(dq:getPolicyTags()) do
        if dq.qname:equal(tag) then
          found = true
        end
        dq:addAnswer(pdns.TXT, '"'..tag..'"')
      end

      if not found then
        pdnslog("not valid tag found")
        dq.rcode = pdns.REFUSED
        return true
      end

      if dq.data['canary'] ~= 'from-gettag' then
        pdnslog("did not get any data from gettag")
        dq.rcode = pdns.REFUSED
        return true
      end

      if dq.qtype == pdns.A then
        dq:addAnswer(pdns.A, '192.0.2.1')
      elseif dq.qtype == pdns.AAAA then
        dq:addAnswer(pdns.AAAA, '2001:db8::1')
      end

      return true
    end
    """

    @classmethod
    def setUpClass(cls):

        cls.setUpSockets()
        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)
        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

    def testA(self):
        name = 'gettag.lua.'
        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [ name, 'gettag-qtype-1'])
            ]
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertResponseMatches(query, expected, res)

    def testTCPA(self):
        name = 'gettag-tcpa.lua.'
        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [ name, 'gettag-qtype-1', 'gettag-tcp'])
            ]
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendTCPQuery(query)
        self.assertResponseMatches(query, expected, res)

    def testAAAA(self):
        name = 'gettag-aaaa.lua.'
        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'AAAA', '2001:db8::1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [ name, 'gettag-qtype-28'])
            ]
        query = dns.message.make_query(name, 'AAAA', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertResponseMatches(query, expected, res)

    def testAAAA(self):
        name = 'gettag-tcpaaaa.lua.'
        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'AAAA', '2001:db8::1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [ name, 'gettag-qtype-28', 'gettag-tcp'])
            ]
        query = dns.message.make_query(name, 'AAAA', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendTCPQuery(query)
        self.assertResponseMatches(query, expected, res)

    def testSubnet(self):
        name = 'gettag-subnet.lua.'
        subnet = '192.0.2.255'
        subnetMask = 32
        ecso = clientsubnetoption.ClientSubnetOption(subnet, subnetMask)
        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [name, 'gettag-qtype-1', 'edns-subnet-' + subnet + '/' + str(subnetMask),
                                                                         'ednsoption-8-count-1', 'ednsoption-8-total-len-8']),
            ]
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[ecso])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertResponseMatches(query, expected, res)

    def testEDNSOptions(self):
        name = 'gettag-ednsoptions.lua.'
        subnet = '192.0.2.255'
        subnetMask = 32
        ecso = clientsubnetoption.ClientSubnetOption(subnet, subnetMask)
        eco1 = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        eco2 = cookiesoption.CookiesOption(b'deadc0de', b'deadc0de')

        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [name, 'gettag-qtype-1', 'edns-subnet-' + subnet + '/' + str(subnetMask),
                                                                         'ednsoption-10-count-2', 'ednsoption-10-total-len-32',
                                                                         'ednsoption-8-count-1', 'ednsoption-8-total-len-8'
                                                                        ]),
            ]
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[eco1,ecso,eco2])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertResponseMatches(query, expected, res)

class GettagRecursorDistributesQueriesTest(GettagRecursorTest):
    _confdir = 'LuaGettagDistributes'
    _config_template = """
    log-common-errors=yes
    gettag-needs-edns-options=yes
    pdns-distributes-queries=yes
    threads=2
    """

hooksReactorRunning = False

class UDPHooksResponder(DatagramProtocol):

    def datagramReceived(self, datagram, address):
        request = dns.message.from_wire(datagram)

        response = dns.message.make_response(request)
        response.flags |= dns.flags.AA

        if request.question[0].name == dns.name.from_text('nxdomain.luahooks.example.'):
            soa = dns.rrset.from_text('luahooks.example.', 86400, dns.rdataclass.IN, 'SOA', 'ns.luahooks.example. hostmaster.luahooks.example. 1 3600 3600 3600 1')
            response.authority.append(soa)
            response.set_rcode(dns.rcode.NXDOMAIN)

        elif request.question[0].name == dns.name.from_text('nodata.luahooks.example.'):
            soa = dns.rrset.from_text('luahooks.example.', 86400, dns.rdataclass.IN, 'SOA', 'ns.luahooks.example. hostmaster.luahooks.example. 1 3600 3600 3600 1')
            response.authority.append(soa)

        elif request.question[0].name == dns.name.from_text('postresolve.luahooks.example.'):
            answer = dns.rrset.from_text('postresolve.luahooks.example.', 3600, dns.rdataclass.IN, 'A', '192.0.2.1')
            response.answer.append(answer)

        self.transport.write(response.to_wire(), address)

class LuaHooksRecursorTest(RecursorTest):
    _confdir = 'LuaHooks'
    _config_template = """
forward-zones=luahooks.example=%s.23
log-common-errors=yes
quiet=no
    """ % (os.environ['PREFIX'])
    _lua_dns_script_file = """

    allowedips = newNMG()
    allowedips:addMask("%s.0/24")

    function ipfilter(remoteip, localip, dh)
      -- allow only 127.0.0.1 and AD=0
      if allowedips:match(remoteip) and not dh:getAD() then
        return false
      end

      return true
    end

    function nodata(dq)
      if dq.qtype == pdns.AAAA and dq.qname == newDN("nodata.luahooks.example.") then
        dq:addAnswer(pdns.AAAA, "2001:DB8::1")
        return true
      end

      return false
    end

    function nxdomain(dq)
      if dq.qtype == pdns.A and dq.qname == newDN("nxdomain.luahooks.example.") then
        dq.rcode=0
        dq:addAnswer(pdns.A, "192.0.2.1")
        return true
      end

      return false
    end

    function postresolve(dq)
      if dq.qtype == pdns.A and dq.qname == newDN("postresolve.luahooks.example.") then
        local records = dq:getRecords()
        for k,v in pairs(records) do
          if v.type == pdns.A and v:getContent() == "192.0.2.1" then
            v:changeContent("192.0.2.42")
            v.ttl=1
          end
	end
        dq:setRecords(records)
        return true
      end

      return false
    end

    function preoutquery(dq)
      if dq.remoteaddr:equal(newCA("%s.23")) and dq.qname == newDN("preout.luahooks.example.") and dq.qtype == pdns.A then
        dq.rcode = -3 -- "kill"
        return true
      end

      return false
    end

    """ % (os.environ['PREFIX'], os.environ['PREFIX'])

    @classmethod
    def startResponders(cls):
        global hooksReactorRunning
        print("Launching responders..")

        address = cls._PREFIX + '.23'
        port = 53

        if not hooksReactorRunning:
            reactor.listenUDP(port, UDPHooksResponder(), interface=address)
            hooksReactorRunning = True

        if not reactor.running:
            cls._UDPResponder = threading.Thread(name='UDP Hooks Responder', target=reactor.run, args=(False,))
            cls._UDPResponder.setDaemon(True)
            cls._UDPResponder.start()

    @classmethod
    def setUpClass(cls):
        cls.setUpSockets()

        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

        print("Launching tests..")

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

    def testNoData(self):
        expected = dns.rrset.from_text('nodata.luahooks.example.', 3600, dns.rdataclass.IN, 'AAAA', '2001:DB8::1')
        query = dns.message.make_query('nodata.luahooks.example.', 'AAAA', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testVanillaNXD(self):
        #expected = dns.rrset.from_text('nxdomain.luahooks.example.', 3600, dns.rdataclass.IN, 'A', '192.0.2.1')
        query = dns.message.make_query('nxdomain.luahooks.example.', 'AAAA', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)

    def testHookedNXD(self):
        expected = dns.rrset.from_text('nxdomain.luahooks.example.', 3600, dns.rdataclass.IN, 'A', '192.0.2.1')
        query = dns.message.make_query('nxdomain.luahooks.example.', 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testPostResolve(self):
        expected = dns.rrset.from_text('postresolve.luahooks.example.', 1, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query('postresolve.luahooks.example.', 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)
            self.assertEqual(res.answer[0].ttl, 1)

    def testIPFilterHeader(self):
        query = dns.message.make_query('ipfiler.luahooks.example.', 'A', 'IN')
        query.flags |= dns.flags.AD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertEqual(res, None)

    def testPreOutInterceptedQuery(self):
        query = dns.message.make_query('preout.luahooks.example.', 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testPreOutNotInterceptedQuery(self):
        query = dns.message.make_query('preout.luahooks.example.', 'AAAA', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)

class LuaHooksRecursorDistributesTest(LuaHooksRecursorTest):
    _confdir = 'LuaHooksDistributes'
    _config_template = """
forward-zones=luahooks.example=%s.23
log-common-errors=yes
pdns-distributes-queries=yes
threads=2
quiet=no
    """ % (os.environ['PREFIX'])

class DNS64Test(RecursorTest):
    """Tests the dq.followupAction("getFakeAAAARecords")"""

    _confdir = 'dns64'
    _config_template = """
    """
    _lua_dns_script_file = """
    prefix = "2001:DB8:64::"

    function nodata (dq)
      if dq.qtype ~= pdns.AAAA then
        return false
      end  --  only AAAA records

      -- don't fake AAAA records if DNSSEC validation failed
      if dq.validationState == pdns.validationstates.Bogus then
         return false
      end

      dq.followupFunction = "getFakeAAAARecords"
      dq.followupPrefix = prefix
      dq.followupName = dq.qname
      return true
    end
    """

    def testAtoAAAA(self):
        expected = [
            dns.rrset.from_text('ns.secure.example.', 15, dns.rdataclass.IN, 'AAAA', '2001:db8:64::7f00:9')
        ]
        query = dns.message.make_query('ns.secure.example', 'AAAA')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)

            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 1)
            self.assertEqual(len(res.authority), 0)
            self.assertResponseMatches(query, expected, res)

    def testAtoCNAMEtoAAAA(self):
        expected = [
            dns.rrset.from_text('cname-to-insecure.secure.example.', 3600, dns.rdataclass.IN, 'CNAME', 'node1.insecure.example.'),
            dns.rrset.from_text('node1.insecure.example.', 3600, dns.rdataclass.IN, 'AAAA', '2001:db8:64::c000:206')
        ]
        query = dns.message.make_query('cname-to-insecure.secure.example.', 'AAAA')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)

            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 2)
            self.assertEqual(len(res.authority), 0)
            self.assertResponseMatches(query, expected, res)


class PDNSRandomTest(RecursorTest):
    """Tests if pdnsrandom works"""

    _confdir = 'pdnsrandom'
    _config_template = """
    """
    _lua_dns_script_file = """
    function preresolve (dq)
      dq.rcode = pdns.NOERROR
      dq:addAnswer(pdns.TXT, pdnsrandom())
      return true
    end
    """

    def testRandom(self):
        query = dns.message.make_query('whatever.example.', 'TXT')

        ans = set()

        ret = self.sendUDPQuery(query)
        ans.add(ret.answer[0])
        ret = self.sendUDPQuery(query)
        ans.add(ret.answer[0])

        self.assertEqual(len(ans), 2)


class PDNSFeaturesTest(RecursorTest):
    """Tests if pdns_features works"""

    _confdir = 'pdnsfeatures'
    _config_template = """
    """
    _lua_dns_script_file = """
    function preresolve (dq)
      dq.rcode = pdns.NOERROR
      -- test pdns_features
      if pdns_features['nonexistent'] ~= nil then
        print('PDNSFeaturesTest: case 1')
        dq.rcode = pdns.SERVFAIL
      end
      if not pdns_features['PR8001_devicename']  then
        print('PDNSFeaturesTest: case 2')
        dq.rcode = pdns.SERVFAIL
      end
      return true
    end
    """

    def testFeatures(self):
        query = dns.message.make_query('whatever.example.', 'TXT')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)

