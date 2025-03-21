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
    _confdir = 'GettagRecursor'
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

      local tm = os.time()
      if dq.queryTime.tv_sec < tm - 1 or dq.queryTime.tv_sec > tm + 1 then
        pdnslog("queryTime is wrong")
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
    _confdir = 'GettagRecursorDistributesQueries'
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

        elif request.question[0].name == dns.name.from_text('preresolve.luahooks.example.'):
            answer = dns.rrset.from_text('preresolve.luahooks.example.', 3600, dns.rdataclass.IN, 'A', '192.0.2.2')
            response.answer.append(answer)

        self.transport.write(response.to_wire(), address)

class LuaHooksRecursorTest(RecursorTest):
    _confdir = 'LuaHooksRecursor'
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

    function preresolve(dq)
      -- test both preresolve hooking and udpQueryResponse
      if dq.qtype == pdns.A and dq.qname == newDN("preresolve.luahooks.example.") then
        dq.followupFunction = "udpQueryResponse"
        dq.udpCallback = "gotUdpResponse"
        dq.udpQueryDest = newCA("%s.23:53")
        -- synthesize query, responder should answer with regular answer
        dq.udpQuery = "\\254\\255\\001\\000\\000\\001\\000\\000\\000\\000\\000\\000\\npreresolve\\008luahooks\\007example\\000\\000\\001\\000\\001"
        return true
      end
      return false
    end

    function gotUdpResponse(dq)
      dq.followupFunction = ""
      if string.len(dq.udpAnswer) == 61 then
        dq:addAnswer(pdns.A, "192.0.2.2")
        return true;
      end
      dq:addAnswer(pdns.A, "0.0.0.0")
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

    """ % (os.environ['PREFIX'], os.environ['PREFIX'], os.environ['PREFIX'])

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

    def testPreResolve(self):
        expected = dns.rrset.from_text('preresolve.luahooks.example.', 1, dns.rdataclass.IN, 'A', '192.0.2.2')
        query = dns.message.make_query('preresolve.luahooks.example.', 'A', 'IN')
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testIPFilterHeader(self):
        query = dns.message.make_query('ipfilter.luahooks.example.', 'A', 'IN')
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
    _confdir = 'LuaHooksRecursorDistributes'
    _config_template = """
forward-zones=luahooks.example=%s.23
log-common-errors=yes
pdns-distributes-queries=yes
threads=2
quiet=no
    """ % (os.environ['PREFIX'])

class LuaDNS64Test(RecursorTest):
    """Tests the dq.followupAction("getFakeAAAARecords")"""

    _confdir = 'LuaDNS64'
    _auth_zones = RecursorTest._default_auth_zones
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

class GettagFFIDNS64Test(RecursorTest):
    """Tests the interaction between gettag_ffi, RPZ and DNS64:
       - gettag_ffi will intercept the query and return a NODATA
       - the RPZ zone will match the name, but the only type is A
       - DNS64 should kick in, generating an AAAA
    """

    _confdir = 'GettagFFIDNS64'
    _config_template = """
    dns64-prefix=64:ff9b::/96
    """
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz." })
    """ % (_confdir)

    _lua_dns_script_file = """
    local ffi = require("ffi")

    ffi.cdef[[
      typedef struct pdns_ffi_param pdns_ffi_param_t;

      void pdns_ffi_param_set_rcode(pdns_ffi_param_t* ref, int rcode);
    ]]

    function gettag_ffi(obj)
      -- fake a NODATA (without SOA) no matter the query
      ffi.C.pdns_ffi_param_set_rcode(obj, 0)
      return {}
    end
    """
    _auth_zones = []

    @classmethod
    def generateRecursorConfig(cls, confdir):
        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
dns64.test.powerdns.com.zone.rpz. 60 IN A 192.0.2.42
""".format(soa=cls._SOA))
        super(GettagFFIDNS64Test, cls).generateRecursorConfig(confdir)

    def testAtoAAAA(self):
        expected = [
            dns.rrset.from_text('dns64.test.powerdns.com.', 15, dns.rdataclass.IN, 'AAAA', '64:ff9b::c000:22a')
        ]
        query = dns.message.make_query('dns64.test.powerdns.com.', 'AAAA')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)

            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 1)
            self.assertEqual(len(res.authority), 0)
            self.assertResponseMatches(query, expected, res)

class PDNSRandomTest(RecursorTest):
    """Tests if pdnsrandom works"""

    _confdir = 'PDNSRandom'
    _config_template = """
    """
    _lua_dns_script_file = """
    function preresolve (dq)
      dq.rcode = pdns.NOERROR
      dq:addAnswer(pdns.TXT, pdnsrandom())
      dq.variable = true
      return true
    end
    """

    def testRandom(self):
        query = dns.message.make_query('whatever.example.', 'TXT')

        ans = set()

        ret = self.sendUDPQuery(query)
        ans.add(ret.answer[0][0])
        ret = self.sendUDPQuery(query)
        ans.add(ret.answer[0][0])

        self.assertEqual(len(ans), 2)


class PDNSFeaturesTest(RecursorTest):
    """Tests if pdns_features works"""

    _confdir = 'PDNSFeatures'
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

class PDNSGeneratingAnswerFromGettagTest(RecursorTest):
    """Tests that we can generate answers from gettag"""

    _confdir = 'PDNSGeneratingAnswerFromGettag'
    _config_template = """
    """
    _lua_dns_script_file = """
    local ffi = require("ffi")

    ffi.cdef[[
      typedef struct pdns_ffi_param pdns_ffi_param_t;

      typedef enum
      {
        answer = 1,
        authority = 2,
        additional = 3
      } pdns_record_place_t;

      const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref);
      void pdns_ffi_param_set_rcode(pdns_ffi_param_t* ref, int rcode);
      bool pdns_ffi_param_add_record(pdns_ffi_param_t *ref, const char* name, uint16_t type, uint32_t ttl, const char* content, size_t contentSize, pdns_record_place_t place);
    ]]

    function gettag_ffi(obj)
      local qname = ffi.string(ffi.C.pdns_ffi_param_get_qname(obj))
      if qname == 'gettag-answers.powerdns.com' then
         ffi.C.pdns_ffi_param_set_rcode(obj, 0)
         ffi.C.pdns_ffi_param_add_record(obj, nil, pdns.A, 60, '192.0.2.1', 9, 1);
         ffi.C.pdns_ffi_param_add_record(obj, "not-powerdns.com.", pdns.A, 60, '192.0.2.2', 9, 3);
      end
    end

    function preresolve (dq)
      -- refused everything if it comes that far
      dq.rcode = pdns.REFUSED
      return true
    end
    """

    def testGettag(self):
        expectedAnswerRecords = [
            dns.rrset.from_text('gettag-answers.powerdns.com.', 60, dns.rdataclass.IN, 'A', '192.0.2.1'),
        ]
        expectedAdditionalRecords = [
            dns.rrset.from_text('not-powerdns.com.', 60, dns.rdataclass.IN, 'A', '192.0.2.2'),
        ]
        query = dns.message.make_query('gettag-answers.powerdns.com.', 'A')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 1)
        self.assertEqual(len(res.authority), 0)
        self.assertEqual(len(res.additional), 1)
        self.assertEqual(res.answer, expectedAnswerRecords)
        self.assertEqual(res.additional, expectedAdditionalRecords)

class PDNSValidationStatesTest(RecursorTest):
    """Tests that we have access to the validation states from Lua"""

    _confdir = 'PDNSValidationStates'
    _config_template = """
dnssec=validate
"""
    _roothints = None
    _lua_config_file = """
    """

    _lua_dns_script_file = """
    function postresolve (dq)
      if pdns.validationstates.Indeterminate == nil or
         pdns.validationstates.BogusNoValidDNSKEY == nil or
         pdns.validationstates.BogusInvalidDenial == nil or
         pdns.validationstates.BogusUnableToGetDSs == nil or
         pdns.validationstates.BogusUnableToGetDNSKEYs == nil or
         pdns.validationstates.BogusSelfSignedDS == nil or
         pdns.validationstates.BogusNoRRSIG == nil or
         pdns.validationstates.BogusNoValidRRSIG == nil or
         pdns.validationstates.BogusMissingNegativeIndication == nil or
         pdns.validationstates.BogusSignatureNotYetValid == nil or
         pdns.validationstates.BogusSignatureExpired == nil or
         pdns.validationstates.BogusUnsupportedDNSKEYAlgo == nil or
         pdns.validationstates.BogusUnsupportedDSDigestType == nil or
         pdns.validationstates.BogusNoZoneKeyBitSet == nil or
         pdns.validationstates.BogusRevokedDNSKEY == nil or
         pdns.validationstates.BogusInvalidDNSKEYProtocol == nil or
         pdns.validationstates.Insecure == nil or
         pdns.validationstates.Secure == nil or
         pdns.validationstates.Bogus == nil then
         -- refused if at least one state is not available
         pdnslog('Missing DNSSEC validation state!')
         dq.rcode = pdns.REFUSED
         return true
      end
      if dq.qname == newDN('brokendnssec.net.') then
        if dq.validationState ~= pdns.validationstates.Bogus then
          pdnslog('DNSSEC validation state should be Bogus!')
          dq.rcode = pdns.REFUSED
          return true
        end
        if dq.detailedValidationState ~= pdns.validationstates.BogusNoRRSIG then
          pdnslog('DNSSEC detailed validation state is not valid, got '..dq.detailedValidationState..' and expected '..pdns.validationstates.BogusNoRRSIG)
          dq.rcode = pdns.REFUSED
          return true
        end
        if not isValidationStateBogus(dq.detailedValidationState) then
          pdnslog('DNSSEC detailed validation state should be Bogus and is not!')
          dq.rcode = pdns.REFUSED
          return true
        end
      end
      return false
    end
    """

    def testValidationBogus(self):
        query = dns.message.make_query('brokendnssec.net.', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertEqual(len(res.answer), 0)
        self.assertEqual(len(res.authority), 0)

class PolicyEventFilterOnFollowUpTest(RecursorTest):
    """Tests the interaction between RPZ and followup queries (dns64, followCNAME)
    """

    _confdir = 'PolicyEventFilterOnFollowUp'
    _auth_zones = RecursorTest._default_auth_zones
    _config_template = """
    """
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz." })
    """ % (_confdir)

    _lua_dns_script_file = """
    function preresolve(dq)
      dq:addAnswer(pdns.CNAME, "secure.example.")
      dq.followupFunction="followCNAMERecords"
      dq.rcode = pdns.NOERROR
      return true
    end

    function policyEventFilter(event)
      event.appliedPolicy.policyKind = pdns.policykinds.NoAction
      return true
    end
    """

    @classmethod
    def generateRecursorConfig(cls, confdir):
        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
secure.example.zone.rpz. 60 IN A 192.0.2.42
""".format(soa=cls._SOA))
        super(PolicyEventFilterOnFollowUpTest, cls).generateRecursorConfig(confdir)

    def testA(self):
        expected = [
            dns.rrset.from_text('policyeventfilter-followup.test.powerdns.com.', 15, dns.rdataclass.IN, 'CNAME', 'secure.example.'),
            dns.rrset.from_text('secure.example.', 15, dns.rdataclass.IN, 'A', '192.0.2.17')
        ]
        query = dns.message.make_query('policyeventfilter-followup.test.powerdns.com.', 'A')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)

            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 2)
            self.assertEqual(len(res.authority), 0)
            self.assertResponseMatches(query, expected, res)

class PolicyEventFilterOnFollowUpWithNativeDNS64Test(RecursorTest):
    """Tests the interaction between followup queries and native dns64
    """

    _confdir = 'PolicyEventFilterOnFollowUpWithNativeDNS64'
    _auth_zones = RecursorTest._default_auth_zones
    _config_template = """
    dns64-prefix=1234::/96
    """
    _lua_config_file = """
    """
    _lua_dns_script_file = """
    function preresolve(dq)
      dq:addAnswer(pdns.CNAME, "cname.secure.example.")
      dq.followupFunction="followCNAMERecords"
      dq.rcode = pdns.NOERROR
      return true
    end

    """

    def testAAAA(self):
        expected = [
            dns.rrset.from_text('mx1.secure.example.', 15, dns.rdataclass.IN, 'CNAME', 'cname.secure.example.'),
            dns.rrset.from_text('cname.secure.example.', 15, dns.rdataclass.IN, 'CNAME', ' host1.secure.example.'),
            dns.rrset.from_text('host1.secure.example.', 15, dns.rdataclass.IN, 'AAAA', '1234::c000:202')
        ]
        query = dns.message.make_query('mx1.secure.example', 'AAAA')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            print(res)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 3)
            self.assertEqual(len(res.authority), 0)
            self.assertResponseMatches(query, expected, res)

class LuaPostResolveFFITest(RecursorTest):
    """Tests postresolve_ffi interface"""

    _confdir = 'LuaPostResolveFFI'
    _auth_zones = RecursorTest._default_auth_zones
    _config_template = """
    """
    _lua_dns_script_file = """
local ffi = require("ffi")

ffi.cdef[[
  typedef struct pdns_postresolve_ffi_handle pdns_postresolve_ffi_handle_t;

  typedef enum
  {
    pdns_record_place_answer = 1,
    pdns_record_place_authority = 2,
    pdns_record_place_additional = 3
  } pdns_record_place_t;

 typedef enum
  {
    pdns_policy_kind_noaction = 0,
    pdns_policy_kind_drop = 1,
    pdns_policy_kind_nxdomain = 2,
    pdns_policy_kind_nodata = 3,
    pdns_policy_kind_truncate = 4,
    pdns_policy_kind_custom = 5
  } pdns_policy_kind_t;

  typedef struct pdns_ffi_record {
    const char* name;
    size_t name_len;
    const char* content;
    size_t content_len;
    uint32_t ttl;
    pdns_record_place_t place;
    uint16_t type;
  } pdns_ffi_record_t;

  const char* pdns_postresolve_ffi_handle_get_qname(pdns_postresolve_ffi_handle_t* ref);
  const char* pdns_postresolve_ffi_handle_get_qname_raw(pdns_postresolve_ffi_handle_t* ref, const char** name, size_t* len);
  uint16_t pdns_postresolve_ffi_handle_get_qtype(const pdns_postresolve_ffi_handle_t* ref);
  uint16_t pdns_postresolve_ffi_handle_get_rcode(const pdns_postresolve_ffi_handle_t* ref);
  void pdns_postresolve_ffi_handle_set_rcode(const pdns_postresolve_ffi_handle_t* ref, uint16_t rcode);
  void pdns_postresolve_ffi_handle_set_appliedpolicy_kind(pdns_postresolve_ffi_handle_t* ref, pdns_policy_kind_t kind);
  bool pdns_postresolve_ffi_handle_get_record(pdns_postresolve_ffi_handle_t* ref, unsigned int i, pdns_ffi_record_t *record, bool raw);
  bool pdns_postresolve_ffi_handle_set_record(pdns_postresolve_ffi_handle_t* ref, unsigned int i, const char* content, size_t contentLen, bool raw);
  void pdns_postresolve_ffi_handle_clear_records(pdns_postresolve_ffi_handle_t* ref);
  bool pdns_postresolve_ffi_handle_add_record(pdns_postresolve_ffi_handle_t* ref, const char* name, uint16_t type, uint32_t ttl, const char* content, size_t contentLen, pdns_record_place_t place, bool raw);
  const char* pdns_postresolve_ffi_handle_get_authip(pdns_postresolve_ffi_handle_t* ref);
  void pdns_postresolve_ffi_handle_get_authip_raw(pdns_postresolve_ffi_handle_t* ref, const void** addr, size_t* addrSize);
]]


function tohex(str)
  return (str:gsub('.', function (c) return string.format('%02X', string.byte(c)) end))
end
function toA(str)
  return (str:gsub('.', function (c) return string.format('%d.', string.byte(c)) end))
end

function postresolve_ffi(ref)
  local qname = ffi.string(ffi.C.pdns_postresolve_ffi_handle_get_qname(ref))
  local qtype = ffi.C.pdns_postresolve_ffi_handle_get_qtype(ref)

  if qname  == "example" and qtype == pdns.SOA
  then
     local addr = ffi.string(ffi.C.pdns_postresolve_ffi_handle_get_authip(ref))
     if string.sub(addr, -3) ~= ".10" and string.sub(addr, -3) ~= ".18"
     then
       -- signal error by clearing all
       ffi.C.pdns_postresolve_ffi_handle_clear_records(ref)
     end
     local qaddr = ffi.new("const char *[1]")
     local qlen = ffi.new("size_t [1]")
     ffi.C.pdns_postresolve_ffi_handle_get_qname_raw(ref, qaddr, qlen)
     local q = ffi.string(qaddr[0], qlen[0])
     if tohex(q) ~= "076578616D706C6500"
     then
       -- pdnslog("Error "..tohex(q))
       -- signal error by clearing all
       ffi.C.pdns_postresolve_ffi_handle_clear_records(ref)
     end
     -- as a bonus check from which auth the data came
     local addr = ffi.new("const void *[1]")
     local len = ffi.new("size_t [1]")
     ffi.C.pdns_postresolve_ffi_handle_get_authip_raw(ref, addr, len)
     local a = ffi.string(addr[0], len[0])
     if string.byte(a, 4) ~= 10 and string.byte(a,4) ~= 18
     then
       -- signal error by clearing all
       ffi.C.pdns_postresolve_ffi_handle_clear_records(ref)
     end
     ffi.C.pdns_postresolve_ffi_handle_set_appliedpolicy_kind(ref, "pdns_policy_kind_noaction")
     return true
  end
  if qname == "example" and qtype == pdns.TXT
  then
     ffi.C.pdns_postresolve_ffi_handle_set_appliedpolicy_kind(ref, "pdns_policy_kind_drop")
     return true
  end
  if qname == "ns1.example" and qtype == pdns.A
  then
     ffi.C.pdns_postresolve_ffi_handle_set_appliedpolicy_kind(ref, "pdns_policy_kind_nxdomain")
     return true
  end
  if qname == "ns1.example" and qtype == pdns.AAAA
  then
     ffi.C.pdns_postresolve_ffi_handle_set_appliedpolicy_kind(ref, "pdns_policy_kind_nodata")
     return true
  end
  if qname == "ns2.example" and qtype == pdns.A
  then
     ffi.C.pdns_postresolve_ffi_handle_set_appliedpolicy_kind(ref, "pdns_policy_kind_truncate")
     return true
  end

  if qname ~= "postresolve_ffi.example" or (qtype ~= pdns.A and qtype ~= pdns.AAAA)
  then
    return false
  end

  local record = ffi.new("pdns_ffi_record_t")
  local i = 0

  while ffi.C.pdns_postresolve_ffi_handle_get_record(ref, i, record, false)
  do
     local content = ffi.string(record.content, record.content_len)
     local name = ffi.string(record.name)
     if name ~= "postresolve_ffi.example"
     then
       return false
     end
     if record.type == pdns.A and content == "1.2.3.4"
     then
       ffi.C.pdns_postresolve_ffi_handle_set_record(ref, i, "0.1.2.3", 7, false);
       ffi.C.pdns_postresolve_ffi_handle_add_record(ref, "add."..name, pdns.A, record.ttl, '4.5.6.7', 7, "pdns_record_place_additional", false);
     elseif record.type == pdns.AAAA and content == "::1"
     then
       ffi.C.pdns_postresolve_ffi_handle_set_record(ref, i, "\\0\\1\\2\\3\\4\\5\\6\\7\\8\\9\\10\\11\\12\\13\\14\\15", 16, true);
     end
     i = i + 1
  end
  -- loop again using raw
  i = 0
  while ffi.C.pdns_postresolve_ffi_handle_get_record(ref, i, record, true)
  do
     local content = ffi.string(record.content, record.content_len)
     local name = ffi.string(record.name, record.name_len)
     --pdnslog("R  "..tohex(name))
     if tohex(name) ~= "0F706F73747265736F6C76655F666669076578616D706C6500"
     then
       ffi.C.pdns_postresolve_ffi_handle_clear_records(ref)
     end
     i = i + 1
  end
  return true
end
    """

    def testNOACTION(self):
        """ postresolve_ffi: test that we can do a NOACTION for a name and type combo"""
        query = dns.message.make_query('example', 'SOA')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 1)

    def testDROP(self):
        """ postresolve_ffi: test that we can do a DROP for a name and type combo"""
        query = dns.message.make_query('example', 'TXT')
        res = self.sendUDPQuery(query)
        self.assertEqual(res, None)

    def testNXDOMAIN(self):
        """ postresolve_ffi: test that we can return a NXDOMAIN for a name and type combo"""
        query = dns.message.make_query('ns1.example', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertEqual(len(res.answer), 0)

    def testNODATA(self):
        """ postresolve_ffi: test that we can return a NODATA for a name and type combo"""
        query = dns.message.make_query('ns1.example', 'AAAA')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 0)

    def testTRUNCATE(self):
        """ postresolve_ffi: test that we can return a truncated for a name and type combo"""
        query = dns.message.make_query('ns2.example', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 0)
        self.assertMessageHasFlags(res, ['QR', 'TC', 'RD', 'RA'])


    def testModifyA(self):
        """postresolve_ffi: test that we can modify A answers"""
        expectedAnswerRecords = [
            dns.rrset.from_text('postresolve_ffi.example.', 60, dns.rdataclass.IN, 'A', '0.1.2.3', '1.2.3.5'),
        ]
        expectedAdditionalRecords = [
            dns.rrset.from_text('add.postresolve_ffi.example.', 60, dns.rdataclass.IN, 'A', '4.5.6.7'),
        ]

        query = dns.message.make_query('postresolve_ffi.example', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 1)
        self.assertEqual(len(res.authority), 0)
        self.assertEqual(len(res.additional), 1)
        self.assertEqual(res.answer, expectedAnswerRecords)
        self.assertEqual(res.additional, expectedAdditionalRecords)

    def testModifyAAAA(self):
        """postresolve_ffi: test that we can modify AAAA answers"""
        expectedAnswerRecords = [
            dns.rrset.from_text('postresolve_ffi.example.', 60, dns.rdataclass.IN, 'AAAA', '1:203:405:607:809:a0b:c0d:e0f', '::2'),
        ]
        query = dns.message.make_query('postresolve_ffi.example', 'AAAA')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 1)
        self.assertEqual(len(res.authority), 0)
        self.assertEqual(len(res.additional), 0)
        self.assertEqual(res.answer, expectedAnswerRecords)
